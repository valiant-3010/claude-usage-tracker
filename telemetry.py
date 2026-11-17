"""Lossless OTLP JSON record storage, derived metrics, and authenticated explorer.

All resource/scope/record fields are retained. Raw data and derived metrics are
separate: logs/traces never get added to metric token totals a second time.
"""
import csv
import hashlib
import html
import io
import json
import math
import time
from datetime import datetime, timezone
from urllib.parse import urlencode

EXTRA_ENV = {
    'OTEL_LOGS_EXPORTER': 'otlp', 'OTEL_TRACES_EXPORTER': 'otlp',
    'CLAUDE_CODE_ENHANCED_TELEMETRY_BETA': '1',
    'OTEL_METRICS_INCLUDE_SESSION_ID': 'true',
    'OTEL_METRICS_INCLUDE_VERSION': 'true',
    'OTEL_METRICS_INCLUDE_ENTRYPOINT': 'true',
    'OTEL_METRICS_INCLUDE_REPOSITORY': 'true',
    'OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE': 'delta',
}
CONTENT_ENV = {k: '1' for k in (
    'OTEL_LOG_USER_PROMPTS', 'OTEL_LOG_ASSISTANT_RESPONSES',
    'OTEL_LOG_TOOL_DETAILS', 'OTEL_LOG_TOOL_CONTENT', 'OTEL_LOG_RAW_API_BODIES')}


def json_safe(v):
    if isinstance(v, float) and not math.isfinite(v):
        return str(v)
    if isinstance(v, list):
        return [json_safe(x) for x in v]
    if isinstance(v, dict):
        return {k:json_safe(x) for k,x in v.items()}
    return v


def dumps(v):
    return json.dumps(json_safe(v), ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def decode(v):
    if not isinstance(v, dict):
        return v
    if 'arrayValue' in v:
        return [decode(x) for x in v['arrayValue'].get('values', [])]
    if 'kvlistValue' in v:
        return attributes(v['kvlistValue'].get('values', []))
    if 'intValue' in v:
        return int(v['intValue'])
    return next(iter(v.values()), None)


def attributes(items):
    return {x['key']: decode(x['value']) for x in items or []}


def initialize(db):
    db.execute('''CREATE TABLE IF NOT EXISTS telemetry_records(
        id INTEGER PRIMARY KEY, fingerprint TEXT UNIQUE NOT NULL,
        signal TEXT NOT NULL, friend TEXT NOT NULL, ts INTEGER NOT NULL,
        received INTEGER NOT NULL, name TEXT NOT NULL, attrs TEXT NOT NULL,
        raw TEXT NOT NULL, value REAL, normalized REAL, kind TEXT,
        series TEXT, start_ns INTEGER, time_ns INTEGER, point_id INTEGER,
        quality TEXT NOT NULL DEFAULT 'recorded')''')
    db.execute('CREATE INDEX IF NOT EXISTS records_time ON telemetry_records(ts,id)')
    db.execute('CREATE INDEX IF NOT EXISTS records_friend ON telemetry_records(friend,ts)')
    db.execute('CREATE INDEX IF NOT EXISTS records_series ON telemetry_records(series,start_ns,time_ns)')
    db.execute('CREATE INDEX IF NOT EXISTS records_signal ON telemetry_records(signal,name,ts)')
    db.execute('CREATE INDEX IF NOT EXISTS points_friend_time ON points(friend,ts)')
    db.execute('CREATE INDEX IF NOT EXISTS points_metric_time ON points(metric,ts)')
    db.execute("CREATE TABLE IF NOT EXISTS usage_snapshots(ts INTEGER NOT NULL,label TEXT NOT NULL,pct REAL NOT NULL,note TEXT,friend TEXT NOT NULL DEFAULT '')")
    if 'friend' not in [c[1] for c in db.execute('PRAGMA table_info(usage_snapshots)')]:
        db.execute("ALTER TABLE usage_snapshots ADD COLUMN friend TEXT NOT NULL DEFAULT ''")
    db.execute('CREATE TABLE IF NOT EXISTS telemetry_meta(key TEXT PRIMARY KEY,value TEXT)')
    if not db.execute("SELECT 1 FROM telemetry_meta WHERE key='legacy_import'").fetchone():
        for pid,ts,friend,metric,typ,model,value in db.execute('SELECT rowid,* FROM points').fetchall():
            a = {k:v for k,v in [('type',typ),('model',model)] if v is not None}
            raw = {'legacy':True,'note':'Original OTLP payload was not stored.',
                   'stored_row':{'ts':ts,'friend':friend,'metric':metric,'type':typ,'model':model,'value':value}}
            db.execute("""INSERT OR IGNORE INTO telemetry_records
                (fingerprint,signal,friend,ts,received,name,attrs,raw,value,normalized,kind,point_id,quality)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                ('legacy:'+str(pid),'metrics',friend,ts,0,'claude_code.'+metric,dumps(a),dumps(raw),value,value,'sum',pid,'legacy: unverified totals'))
        db.execute("INSERT INTO telemetry_meta VALUES('legacy_import','1')")


USAGE_LABELS = ['Claude Design (weekly limit)', 'Overall weekly limit', 'Claude Code share', 'Chats share', 'Cowork share', 'Other share']


def members(db):
    return [r[0] for r in db.execute('SELECT DISTINCT friend FROM points ORDER BY friend')]


def add_snapshot(db, friend, label, pct, note=''):
    """Hand-entered reading from claude.ai/settings/usage (Pro has no API). Percentages, never tokens."""
    pct = number(pct)
    if friend not in members(db) or label not in USAGE_LABELS or pct is None or not 0 <= pct <= 100:
        raise ValueError('Pick a member, a reading and a percentage from 0 to 100')
    db.execute('INSERT INTO usage_snapshots(ts,label,pct,note,friend) VALUES(?,?,?,?,?)', (int(time.time()), label, pct, note[:200], friend))


def number(v):
    try:
        n = float(v)
        return n if math.isfinite(n) else None
    except (ValueError, TypeError, OverflowError):
        return None


def ingest(db, payload, friend, signal):
    if not isinstance(payload, dict):
        raise ValueError('Expected an OTLP object')
    root, scopes, records = {
        'metrics': ('resourceMetrics', 'scopeMetrics', 'metrics'),
        'logs': ('resourceLogs', 'scopeLogs', 'logRecords'),
        'traces': ('resourceSpans', 'scopeSpans', 'spans'),
    }[signal]
    if root not in payload or not isinstance(payload[root], list):
        raise ValueError('Wrong OTLP signal')
    initialize(db)
    dirty = set()
    for resource in payload[root]:
        ra = attributes(resource.get('resource', {}).get('attributes'))
        for scope in resource.get(scopes, []):
            sa = attributes(scope.get('scope', {}).get('attributes'))
            for record in scope.get(records, []):
                kinds = [k for k in ('sum', 'gauge', 'histogram', 'exponentialHistogram', 'summary') if k in record] if signal == 'metrics' else ['event']
                for kind in kinds:
                    container = record[kind] if signal == 'metrics' else {}
                    for dp in container.get('dataPoints', []) if signal == 'metrics' else [record]:
                        a = {**ra, **sa, **attributes(dp.get('attributes'))}
                        for raw_key, key in [('traceId','otlp.trace_id'),('spanId','otlp.span_id'),('parentSpanId','otlp.parent_span_id'),('severityText','otlp.severity'),('severityNumber','otlp.severity_number')]:
                            if raw_key in dp:
                                a[key] = dp[raw_key]
                        if signal == 'traces' and 'status' in dp:
                            a['otlp.status'] = dp['status']
                        ts_ns = int(dp.get('timeUnixNano') or dp.get('endTimeUnixNano') or dp.get('observedTimeUnixNano') or time.time_ns())
                        if not 0 <= ts_ns <= 9223372036854775807:
                            raise ValueError('Timestamp outside SQLite range')
                        start = int(dp.get('startTimeUnixNano') or 0)
                        if not 0 <= start <= 9223372036854775807:
                            raise ValueError('Start timestamp outside SQLite range')
                        name = record.get('name') or a.get('event.name') or record.get('eventName') or 'log'
                        if signal == 'logs' and name == 'log':
                            body = decode(dp.get('body', {}))
                            if isinstance(body, str) and body.startswith('claude_code.'):
                                name = body
                        raw = {
                            'resource': {k:v for k,v in resource.items() if k != scopes},
                            'scope': {k:v for k,v in scope.items() if k != records},
                            'record': record if signal != 'metrics' else {k:v for k,v in record.items() if k not in kinds},
                        }
                        if signal == 'metrics':
                            raw['record'][kind] = {**{k:v for k,v in container.items() if k != 'dataPoints'}, 'dataPoints':[dp]}
                        fingerprint = hashlib.sha256(dumps([friend, signal, raw]).encode()).hexdigest()
                        metric_name = str(name).removeprefix('claude_code.')
                        v = number(dp.get('asDouble', dp.get('asInt'))) if kind in ('sum','gauge') else None
                        temp = container.get('aggregationTemporality', 0)
                        cumulative = kind == 'sum' and temp in (2, 'AGGREGATION_TEMPORALITY_CUMULATIVE')
                        quality = 'cumulative' if cumulative else 'gauge' if kind == 'gauge' else 'delta' if temp in (1, 'AGGREGATION_TEMPORALITY_DELTA') else 'temporality unspecified' if kind == 'sum' else 'raw only'
                        if kind == 'sum' and (v is None or v >= 1e12 or (v < 0 and metric_name in ('token.usage','cost.usage','session.count','active_time.total'))):  # 1e12 cap: one bad client can't poison the totals
                            quality = 'invalid numeric value'
                            v = None
                        series = hashlib.sha256(dumps([friend, raw['resource'], raw['scope'], name, kind, a]).encode()).hexdigest() if signal == 'metrics' else None
                        cur = db.execute('''INSERT OR IGNORE INTO telemetry_records
                            (fingerprint,signal,friend,ts,received,name,attrs,raw,value,normalized,kind,series,start_ns,time_ns,quality)
                            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                            (fingerprint,signal,friend,ts_ns//10**9,int(time.time()),str(name),dumps(a),dumps(raw),v,None,kind,series,start,ts_ns,quality))
                        if not cur.rowcount:
                            continue
                        rid = cur.lastrowid
                        # Only sums are additive. Gauges/histograms stay fully inspectable.
                        if kind == 'sum' and v is not None:
                            cur = db.execute('INSERT INTO points VALUES(?,?,?,?,?,?)',
                                (ts_ns//10**9,friend,metric_name,str(a['type'])[:32] if 'type' in a else None,str(a['model'])[:64] if 'model' in a else None,0 if cumulative else v))
                            db.execute('UPDATE telemetry_records SET point_id=?,normalized=? WHERE id=?', (cur.lastrowid,0 if cumulative else v,rid))
                            if cumulative:
                                dirty.add((series,start))
    for series,start in dirty:
        # Reconcile in timestamp order so late arrivals and exporter retries cannot inflate totals.
        previous = 0
        rows = db.execute("SELECT id,point_id,value,time_ns,raw FROM telemetry_records WHERE series=? AND start_ns=? AND quality='cumulative' AND point_id IS NOT NULL ORDER BY time_ns,id", (series,start)).fetchall()
        for index,(rid,pid,v,ts,raw) in enumerate(rows):
            # A corrected sample at the same time supersedes its earlier value.
            superseded = index + 1 < len(rows) and rows[index+1][3] == ts
            monotonic = json.loads(raw)['record']['sum'].get('isMonotonic', True)
            delta = 0 if superseded else v - previous if v >= previous or not monotonic else v
            db.execute('UPDATE points SET value=? WHERE rowid=?', (delta,pid))
            db.execute('UPDATE telemetry_records SET normalized=? WHERE id=?', (delta,rid))
            if not superseded:
                previous = v



ESC = lambda x: html.escape(str(x), quote=True)


def table(headers, rows):
    return '<div class="tw"><table><thead><tr>'+''.join('<th>'+ESC(h)+'</th>' for h in headers)+'</tr></thead><tbody>'+''.join('<tr>'+''.join('<td>'+ESC(v if v is not None else '—')+'</td>' for v in row)+'</tr>' for row in rows)+'</tbody></table></div>'


def stamp(ts):
    try:
        return 'Unknown (legacy)' if not ts else datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except (ValueError, OSError, OverflowError):
        return str(ts)


def params(q):
    return {k:v[0] for k,v in q.items() if v}


def filters(q, alias='r'):
    clauses, values = ['1=1'], []
    for field in ('friend', 'signal', 'name'):
        if q.get(field):
            clauses.append(f'{alias}.{field}=?'); values.append(q[field])
    for key,op in (('from','>='),('to','<')):
        if q.get(key):
            try:
                ts = int(datetime.strptime(q[key], '%Y-%m-%d').replace(tzinfo=timezone.utc).timestamp())
            except ValueError:
                raise ValueError('Dates must use YYYY-MM-DD')
            clauses.append(f'{alias}.ts{op}?'); values.append(ts+(86400 if key=='to' else 0))
    if q.get('key'):
        clauses.append(f'EXISTS(SELECT 1 FROM json_each({alias}.attrs) j WHERE j.key=?'+(' AND CAST(j.value AS TEXT)=?' if q.get('value') else '')+')')
        values.append(q['key'])
        if q.get('value'): values.append(q['value'])
    if q.get('search'):
        clauses.append(f'({alias}.raw LIKE ? OR {alias}.name LIKE ?)')
        values.extend(['%'+q['search']+'%']*2)
    return ' AND '.join(clauses), values


def url(q, **changes):
    return '/explore?'+urlencode({k:v for k,v in {**q,**changes}.items() if v not in ('',None)})


def link(q, label, **changes):
    return '<a href="'+ESC(url(q,**changes))+'">'+ESC(label)+'</a>'


def page(db, query):
    q = params(query); where, args = filters(q)
    offset = max(0, int(q.get('offset','0')))
    tab = q.get('tab','overview')
    nav = '<nav class="range">'+''.join(link(q, label, tab=t,offset=0) for t,label in [('overview','Overview'),('dimensions','Projects & sessions'),('records','All records'),('catalog','Field catalog'),('usage','Claude app usage'),('health','Collection & setup')])+'</nav>'
    fields = [('friend','Member'),('name','Metric / event name'),('from','From (UTC)'),('to','Through (UTC)'),('key','Attribute key'),('value','Attribute value'),('search','Search raw data')]
    form = '<form class="explorer-filters" action="/explore"><input type="hidden" name="tab" value="'+ESC(tab)+'">'
    for k,label in fields:
        form += '<label>'+label+'<input name="'+k+'" type="'+('date' if k in ('from','to') else 'text')+'" value="'+ESC(q.get(k,''))+'"></label>'
    form += '<label>Signal<select name="signal">'+''.join('<option value="'+x+'"'+(' selected' if q.get('signal','')==x else '')+'>'+label+'</option>' for x,label in [('', 'All'),('metrics','Metrics'),('logs','Events'),('traces','Traces')])+'</select></label><button>Apply filters</button><a href="/explore">Reset</a></form>'
    count = db.execute('SELECT COUNT(*) FROM telemetry_records r WHERE '+where,args).fetchone()[0]
    base = '<header class="top"><h1>Telemetry explorer</h1><a href="/">Leaderboard</a></header>'+nav+form+f'<p class="note">{count:,} matching records. Times are UTC. Historical records lack attributes that the old collector discarded.</p>'
    base += '<p>'+link(q,'Download all matching records (NDJSON)',format='ndjson',offset=0)+' · '+link(q,'Download JSON page',format='json',offset=offset)+' · '+link(q,'Download CSV page',format='csv',offset=offset)+'</p>'
    if q.get('id'):
        row=db.execute('SELECT id,signal,friend,ts,received,name,attrs,raw,value,normalized,quality FROM telemetry_records r WHERE id=? AND '+where,[int(q['id']),*args]).fetchone()
        if not row: return base+'<p>Record not found in these filters.</p>'
        keys=['id','signal','member','recorded','received','name','attributes','raw','value','counted delta','quality']
        obj=dict(zip(keys,row));obj['attributes']=json.loads(obj['attributes']);obj['raw']=json.loads(obj['raw'])
        return base+'<h2>Record '+str(row[0])+'</h2><pre class="raw">'+ESC(json.dumps(obj,indent=2,ensure_ascii=False))+'</pre>'+link(q,'Back to records',id=None,tab='records')
    if tab=='records':
        rows=db.execute('SELECT id,ts,friend,signal,name,value,normalized,quality,attrs FROM telemetry_records r WHERE '+where+' ORDER BY ts DESC,id DESC LIMIT 100 OFFSET ?',[*args,offset]).fetchall()
        base+='<h2>Every received record</h2><p>Open a record for its complete resource, scope, attributes, body, events, links, and original values.</p>'
        for rid,ts,friend,signal,name,v,delta,quality,a in rows:
            base+='<details class="record"><summary>'+ESC(f'{stamp(ts)} · {friend} · {signal} · {name}')+'</summary><p>'+ESC(f'Value: {v} · Counted delta: {delta} · {quality}')+'</p><pre class="raw">'+ESC(json.dumps(json.loads(a),indent=2,ensure_ascii=False))+'</pre>'+link(q,'Open full record',id=rid)+'</details>'
        if not rows: base+='<p>No records match. Broaden the filters or enable the exporters in Collection & setup.</p>'
        base+=pagination(q,offset,count)
    elif tab=='catalog':
        rows=db.execute('SELECT j.key,COUNT(*),COUNT(DISTINCT CAST(j.value AS TEXT)) FROM telemetry_records r,json_each(r.attrs) j WHERE '+where+' GROUP BY j.key ORDER BY j.key LIMIT 100 OFFSET ?',[*args,offset]).fetchall()
        total=db.execute('SELECT COUNT(DISTINCT j.key) FROM telemetry_records r,json_each(r.attrs) j WHERE '+where,args).fetchone()[0]
        base+='<h2>Every observed attribute</h2><p>Resource, scope, and record attributes are searchable. The original fields are preserved in each raw record, including nested fields.</p>'+table(['Attribute','Records','Distinct values'],rows)+pagination(q,offset,total)
        base+='<h2>Signals and names</h2>'+table(['Signal','Name','Records'],db.execute('SELECT signal,name,COUNT(*) FROM telemetry_records r WHERE '+where+' GROUP BY signal,name ORDER BY signal,name',args))
    elif tab=='dimensions':
        dimension=q.get('dimension','session.id')
        base+='<h2>Break down usage</h2><p>'+ ' · '.join(link(q,label,dimension=k,offset=0) for k,label in [('session.id','Sessions'),('vcs.repository.url.full','Repositories'),('model','Models'),('query_source','Main / subagent / auxiliary'),('agent.name','Agents'),('skill.name','Skills'),('plugin.name','Plugins'),('mcp_server.name','MCP servers'),('app.entrypoint','CLI / desktop'),('effort','Effort'),('speed','Speed'),('otlp.trace_id','Trace IDs')])+'</p>'
        base+='<form action="/explore">'+''.join('<input type="hidden" name="'+ESC(k)+'" value="'+ESC(v)+'">' for k,v in q.items() if k not in ('dimension','offset','id','tab'))+'<input type="hidden" name="tab" value="dimensions"><label>Any attribute key <input name="dimension" value="'+ESC(dimension)+'"></label><button>Group</button></form>'
        rows=db.execute('''SELECT CAST(j.value AS TEXT),COUNT(*),
            SUM(CASE WHEN r.name='claude_code.token.usage' THEN r.normalized END),
            SUM(CASE WHEN r.name='claude_code.cost.usage' THEN r.normalized END),MIN(r.ts),MAX(r.ts)
            FROM telemetry_records r,json_each(r.attrs) j WHERE j.key=? AND '''+where+''' GROUP BY CAST(j.value AS TEXT) ORDER BY 3 DESC,2 DESC LIMIT 100 OFFSET ?''',[dimension,*args,offset]).fetchall()
        base+='<p>Token/cost totals use metrics only. Missing values mean that dimension was not supplied.</p>'
        base+=table([dimension,'Records','Tokens','Est. USD','First UTC','Last UTC'],[(v,c,t,round(cost,6) if cost is not None else None,stamp(first),stamp(last)) for v,c,t,cost,first,last in rows])
        base+='<p>'+ ' · '.join(link(q,str(r[0]),tab='records',key=dimension,value=r[0],offset=0) for r in rows)+'</p>'
        total=db.execute('SELECT COUNT(DISTINCT CAST(j.value AS TEXT)) FROM telemetry_records r,json_each(r.attrs) j WHERE j.key=? AND '+where,[dimension,*args]).fetchone()[0]
        base+=pagination(q,offset,total)
        if not rows: base+='<p>This attribute has not been received. Check the field catalog for the exact keys your version emits.</p>'
    elif tab=='usage':
        base+=usage(db)
    elif tab=='health':
        base+=health(db)
    else:
        base+=overview(db,where,args)
    return base


def pagination(q,offset,count):
    return '<p>'+ (link(q,'← Previous',offset=max(0,offset-100)) if offset else '')+' '+(link(q,'Next 100 →',offset=offset+100) if offset+100<count else '')+f' · {min(offset+1,count)}–{min(offset+100,count)} of {count:,}</p>'


def overview(db,where,args):
    out='<h2>Signal coverage</h2>'+table(['Signal','Records','Last received'],[(s,c,stamp(t)) for s,c,t in db.execute('SELECT signal,COUNT(*),MAX(received) FROM telemetry_records r WHERE '+where+' GROUP BY signal',args)])
    out+='<h2>All metrics</h2><p>Sums show counted increments; gauges show their latest sample. Histograms and summaries remain available in raw records.</p>'
    out+=table(['Name','Kind','Samples','Counted total','Min sample','Max sample'],db.execute("SELECT name,kind,COUNT(*),SUM(normalized),MIN(value),MAX(value) FROM telemetry_records r WHERE signal='metrics' AND "+where+' GROUP BY name,kind',args))
    gauges=db.execute("SELECT name,value,ts FROM telemetry_records r WHERE kind='gauge' AND "+where+' ORDER BY ts DESC,id DESC LIMIT 100',args).fetchall()
    if gauges:out+='<h3>Recent gauges</h3>'+table(['Name','Value','UTC'],[(a,b,stamp(c)) for a,b,c in gauges])
    out+='<h2>Events and errors</h2>'+table(['Event','Count'],db.execute("SELECT name,COUNT(*) FROM telemetry_records r WHERE signal='logs' AND "+where+' GROUP BY name ORDER BY 2 DESC',args))
    duration="(SELECT CAST(j.value AS REAL) FROM json_each(r.attrs) j WHERE j.key='duration_ms')"
    out+='<h2>Event durations</h2>'+table(['Event','Timed records','Average ms','Maximum ms'],db.execute(f"SELECT name,COUNT({duration}),ROUND(AVG({duration}),2),MAX({duration}) FROM telemetry_records r WHERE signal='logs' AND "+where+f' GROUP BY name HAVING COUNT({duration})>0',args))
    out+='<h2>Trace spans</h2>'+table(['Span','Count','Average duration ms','Maximum duration ms'],db.execute("SELECT name,COUNT(*),ROUND(AVG((CAST(json_extract(raw,'$.record.endTimeUnixNano') AS REAL)-CAST(json_extract(raw,'$.record.startTimeUnixNano') AS REAL))/1000000),2),ROUND(MAX((CAST(json_extract(raw,'$.record.endTimeUnixNano') AS REAL)-CAST(json_extract(raw,'$.record.startTimeUnixNano') AS REAL))/1000000),2) FROM telemetry_records r WHERE signal='traces' AND "+where+' GROUP BY name',args))
    now=int(time.time());day0=now//86400*86400
    out+='<h2>Usage trends · UTC calendar days</h2>'
    trends=[]
    for label,start,end,previous_start,previous_end in [('Today vs yesterday',day0,now,day0-86400,day0),('Last 7 days vs previous 7',day0-6*86400,now,day0-13*86400,day0-6*86400)]:
        current=db.execute("SELECT SUM(normalized) FROM telemetry_records r WHERE name='claude_code.token.usage' AND ts>=? AND ts<=? AND "+where,[start,end,*args]).fetchone()[0]
        previous=db.execute("SELECT SUM(normalized) FROM telemetry_records r WHERE name='claude_code.token.usage' AND ts>=? AND ts<? AND "+where,[previous_start,previous_end,*args]).fetchone()[0]
        trends.append((label,current,previous,f'{100*((current or 0)-previous)/previous:+.1f}%' if previous and current is not None else 'Unavailable'))
    out+=table(['Period (current period incomplete)','Current tokens','Previous tokens','Change'],trends)
    out+='<h2>Hourly activity · IST</h2><p>Each cell shows recorded metric tokens, not subscription capacity.</p>'
    hours=db.execute("SELECT strftime('%w',ts,'unixepoch','+330 minutes'),strftime('%H',ts,'unixepoch','+330 minutes'),SUM(normalized) FROM telemetry_records r WHERE name='claude_code.token.usage' AND "+where+' GROUP BY 1,2',args).fetchall()
    lookup={(int(d),int(h)):v or 0 for d,h,v in hours}; peak=max(list(lookup.values())+[1])
    out+='<div class="tw"><table><tr><th>IST</th>'+''.join(f'<th>{h:02}</th>' for h in range(24))+'</tr>'
    for d,day in enumerate(['Sun','Mon','Tue','Wed','Thu','Fri','Sat']):
        out+='<tr><th>'+day+'</th>'+''.join(f'<td><button class="heat" title="{day} {h:02}:00 IST: {lookup.get((d,h),0):,.0f} tokens" aria-label="{day} {h:02}:00 IST: {lookup.get((d,h),0):,.0f} tokens" style="background:rgba(80,140,210,{.08+.75*lookup.get((d,h),0)/peak:.2f})">{lookup.get((d,h),0):,.0f}</button></td>' for h in range(24))+'</tr>'
    out+='</table></div><h2>Member shares · filtered metric tokens</h2>'
    shares=db.execute("SELECT friend,SUM(normalized) FROM telemetry_records r WHERE name='claude_code.token.usage' AND "+where+' GROUP BY friend ORDER BY 2 DESC',args).fetchall(); total=sum(v or 0 for _,v in shares)
    out+=table(['Member','Tokens','Share'],[(f,v,f'{100*(v or 0)/total:.1f}%' if total else '—') for f,v in shares])
    out+='<h2>Daily tokens and cost</h2>'+table(['UTC day','Tokens','Est. USD'],db.execute("SELECT date(ts,'unixepoch'),SUM(CASE WHEN name='claude_code.token.usage' THEN normalized END),SUM(CASE WHEN name='claude_code.cost.usage' THEN normalized END) FROM telemetry_records r WHERE "+where+' GROUP BY 1 ORDER BY 1 DESC',args))
    cache=db.execute("SELECT SUM(CASE WHEN j.value='cacheRead' THEN normalized END),SUM(CASE WHEN j.value IN ('input','cacheRead','cacheCreation') THEN normalized END) FROM telemetry_records r,json_each(r.attrs) j WHERE r.name='claude_code.token.usage' AND j.key='type' AND "+where,args).fetchone()
    out+='<p>Cache reuse: '+(f'{100*(cache[0] or 0)/cache[1]:.1f}% of recorded input-side tokens' if cache[1] else 'Unavailable')+'</p>'
    return out


def readings(db, friend=None):
    """[(ts, friend, label, pct, change, note)] oldest first; change compares with the previous reading of the same member+label."""
    last, rows = {}, []
    for ts,f,label,pct,note in db.execute('SELECT ts,friend,label,pct,note FROM usage_snapshots WHERE friend=? OR ?IS NULL ORDER BY ts,rowid',(friend,friend)):
        before = last.get((f,label)); last[(f,label)] = pct
        rows.append((ts,f,label,pct,'—' if before is None else f'{pct-before:+.1f} pts' if pct>=before else 'reset?',note or '—'))
    return rows


def usage(db):
    out='<h2>Claude app usage (manual)</h2><p>Claude Pro has no usage API, so copy a reading from <b>claude.ai/settings/usage</b> before and after a session. These are percentages as shown there, not tokens, and are kept apart from the Claude Code totals. Weekly bars reset, so a drop between readings means a new week.</p>'
    out+='<form class="explorer-filters" method="post" action="/usage"><label>Member<select name="friend">'+''.join('<option>'+ESC(m)+'</option>' for m in members(db))+'</select></label><label>Reading<select name="label">'+''.join('<option>'+ESC(x)+'</option>' for x in USAGE_LABELS)+'</select></label><label>Percent<input name="pct" type="number" min="0" max="100" step="any" required></label><label>Note<input name="note" maxlength="200"></label><button>Save reading</button></form>'
    return out+table(['Recorded','Member','Reading','Percent','Change since previous','Note'],[(stamp(ts),f,label,f'{pct:g}%',change,note) for ts,f,label,pct,change,note in readings(db)[::-1]])


def usage_summary(db, friend):
    """Latest manual reading per label for one member, for the member detail page."""
    latest = {}
    for r in readings(db, friend):
        latest[r[2]] = r
    rows = [(label, f'{latest[label][3]:g}%', latest[label][4], stamp(latest[label][0])) for label in USAGE_LABELS if label in latest]
    return ('<h2>Claude app usage · manual readings</h2><p class="note">Copied by hand from claude.ai/settings/usage. Percentages, not tokens. '
            '<a href="/explore?tab=usage">Add or view all readings</a></p>'
            + (table(['Reading','Latest','Change since previous','Recorded'], rows) if rows else '<p>No readings yet.</p>'))


def health(db):
    legacy=db.execute("SELECT COUNT(*) FROM telemetry_records WHERE quality='legacy: unverified totals'").fetchone()[0]
    out='<h2>Collection status</h2>'+table(['Signal','Records','Last receipt UTC'],[(s,c,stamp(t)) for s,c,t in db.execute('SELECT signal,COUNT(*),MAX(received) FROM telemetry_records GROUP BY signal')])
    out+=f'<p>{legacy:,} legacy rows have no original payload. Their stored values are included in the explorer and leaderboard; missing historical attributes cannot be recovered.</p>'
    out+='<p>New data preserves every OTLP JSON field received. Duplicate records are ignored. Cumulative sums are converted to increments; gauges are not summed. Historical counting is unchanged.</p>'
    out+=table(['Quality','Records'],db.execute('SELECT quality,COUNT(*) FROM telemetry_records GROUP BY quality'))
    out+='<h2>Enable all metadata signals</h2><p>Merge these environment settings into each member’s Claude Code user settings, keeping the existing endpoint and upload token. Restart Claude Code. The server must accept /v1/metrics, /v1/logs, and /v1/traces through your HTTPS proxy.</p><pre class="raw">'+ESC(json.dumps({'env':EXTRA_ENV},indent=2))+'</pre>'
    out+='<h2>Optional full conversation and tool content</h2><p>The collector can display these fields if exported. These additional settings send prompts, responses, commands, tool content, and API bodies to this dashboard. Apply only to accounts whose content you intend to collect. Exporter truncation limits still apply.</p><pre class="raw">'+ESC(json.dumps({'env':CONTENT_ENV},indent=2))+'</pre>'
    out+='<h2>Unavailable sources</h2><p>Claude Design web/app tokens, Claude chat usage, subscription quota remaining, and reset times are not supplied by this Claude Code collector. Missing telemetry is not zero usage.</p><p>Feature availability depends on Claude Code version and the originating app. Only records actually received appear in the explorer.</p>'
    return out


def export_page(db,query):
    q=params(query);where,args=filters(q);offset=max(0,int(q.get('offset','0')))
    cursor=db.execute('SELECT id,signal,friend,ts,received,name,attrs,raw,value,normalized,kind,quality FROM telemetry_records r WHERE '+where+' ORDER BY ts DESC,id DESC LIMIT 101 OFFSET ?',[*args,offset])
    keys=[d[0] for d in cursor.description];rows=[dict(zip(keys,r)) for r in cursor.fetchall()];more=len(rows)>100;rows=rows[:100]
    for r in rows:r['attrs']=json.loads(r['attrs']);r['raw']=json.loads(r['raw'])
    nxt=url(q,offset=offset+100) if more else None
    if q.get('format')=='csv':
        f=io.StringIO();w=csv.writer(f);w.writerow(keys)
        for r in rows:
            vals=[]
            for k in keys:
                v=dumps(r[k]) if isinstance(r[k],dict) else str(r[k]) if r[k] is not None else ''
                vals.append("'"+v if v.startswith(('=','+','-','@','\t','\r')) else v)
            w.writerow(vals)
        return f.getvalue().encode(),'text/csv; charset=utf-8','telemetry.csv',nxt
    return dumps({'records':rows,'next':nxt,'page_size':100}).encode(),'application/json','telemetry.json',nxt


STYLE='''
.explorer-filters{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:.7rem;margin:1rem 0}
.explorer-filters label{font-size:.8rem}.explorer-filters input,.explorer-filters select{display:block;width:100%}
input,select,button{font:inherit;padding:.45rem;border-radius:5px;border:1px solid var(--rule);color:var(--ink);background:var(--chalk)}
.raw{white-space:pre-wrap;overflow-wrap:anywhere;max-height:36rem;overflow:auto;background:var(--rule);padding:1rem;border-radius:8px;font-size:.8rem}
.record{border-bottom:1px solid var(--rule)}.record summary{overflow-wrap:anywhere}.heat{font-size:.7rem;min-width:2rem;padding:.3rem}
'''


def export_all(db, query):
    where,args=filters(params(query))
    cur=db.execute('SELECT id,signal,friend,ts,received,name,attrs,raw,value,normalized,kind,quality FROM telemetry_records r WHERE '+where+' ORDER BY ts,id',args)
    keys=[d[0] for d in cur.description]
    for row in cur:
        obj=dict(zip(keys,row));obj['attrs']=json.loads(obj['attrs']);obj['raw']=json.loads(obj['raw'])
        yield (dumps(obj)+'\n').encode()
