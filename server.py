"""Receives Claude Code OTLP/JSON metrics, stores them in SQLite, shows a per-friend dashboard.

  VIEW_KEY=<dashboard password> python3 server.py       # 127.0.0.1:4318, put Caddy/HTTPS in front
  python3 server.py --add NAME [https://your.domain]    # new friend: saves their token in tokens.txt, prints their settings
  python3 server.py --check                             # self-test

Every friend has their OWN upload token in tokens.txt ("name token" per line; delete a line to revoke, no restart needed).
The server takes the friend's name from the token, so nobody can post as someone else, and a token can't read anything.
VIEW_KEY is the dashboard password, yours alone.

POST /v1/logs, /v1/traces        Events and trace spans, same upload-token authentication
GET /explore                   Filter, inspect, and export all telemetry
POST /v1/metrics                (Authorization: Bearer <friend's token>)  <- Claude Code exporter
POST /login                     form field `key` = VIEW_KEY -> session cookie (the key never appears in a URL)
GET  /?range=today|7d|all       race lanes, one per member
GET  /friend?name=<name>        one member's detail
GET  /fonts/<file>.woff2        self-hosted fonts from ./fonts, so no third-party requests
"""
import telemetry
import base64, hashlib, hmac, html, json, os, re, secrets, sqlite3, sys, time, zlib
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

VIEW_KEY = os.environ.get("VIEW_KEY", "")
TOKENS_FILE = os.environ.get("TOKENS_FILE", "tokens.txt")
DB = os.environ.get("DB", "usage.db")
PORT = int(os.environ.get("PORT", "4318"))
MAX_BODY = 4 << 20
MAX_DB = int(os.environ.get("MAX_DB_MB", "200")) << 20  # uploads refused past this: a rogue token can't fill the disk
METRICS = {"token.usage", "cost.usage", "session.count", "active_time.total"}
SCHEMA = "CREATE TABLE IF NOT EXISTS points(ts INTEGER, friend TEXT, metric TEXT, type TEXT, model TEXT, value REAL)"


UI_SCRIPT = """
document.querySelectorAll('.day-button').forEach(button => {
  const select = () => {
    const chart = button.closest('.daily-chart');
    chart.querySelectorAll('.day-button').forEach(b => b.setAttribute('aria-pressed', String(b === button)));
    chart.querySelector('.day-details').textContent = button.dataset.details;
  };
  button.addEventListener('pointerenter', select);
  button.addEventListener('focus', select);
  button.addEventListener('click', select);
  button.addEventListener('keydown', event => {
    const buttons = [...button.closest('.day-bars').querySelectorAll('button')];
    let index = buttons.indexOf(button);
    if (event.key === 'ArrowRight') index = Math.min(index + 1, buttons.length - 1);
    else if (event.key === 'ArrowLeft') index = Math.max(index - 1, 0);
    else if (event.key === 'Home') index = 0;
    else if (event.key === 'End') index = buttons.length - 1;
    else return;
    event.preventDefault(); buttons[index].focus();
  });
});
"""
SCRIPT_HASH = base64.b64encode(hashlib.sha256(UI_SCRIPT.encode()).digest()).decode()

SEC_HEADERS = [
    ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; font-src 'self'; "
     f"script-src 'sha256-{SCRIPT_HASH}'; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
    ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"), ("X-Frame-Options", "DENY"), ("Cache-Control", "no-store")]


def same(a, b):
    return bool(b) and hmac.compare_digest(a.encode(), b.encode())


def bearer(header):
    return header[7:] if header.startswith("Bearer ") else ""


def session():
    """Cookie value, derived from VIEW_KEY so a stolen cookie never reveals the key (or the upload token)."""
    return hmac.new(VIEW_KEY.encode(), b"dashboard-session", "sha256").hexdigest() if VIEW_KEY else ""


def unzip(raw):
    d = zlib.decompressobj(31)  # 31 = gzip wrapper
    out = d.decompress(raw, MAX_BODY)  # capped, so a tiny gzip bomb can't eat the 1 GB box
    if d.unconsumed_tail:
        raise ValueError("decompressed body too large")
    return out


NAME = r"[A-Za-z0-9_.-]{1,32}"
WINDOW, LIMIT = 900, 5  # 5 wrong secrets from one address -> 15 minutes of 429s
FAILS = {}  # client ip -> (failures, window start); in memory, so a restart clears it


def blocked(ip):
    count, t0 = FAILS.get(ip, (0, 0))
    return count >= LIMIT and time.time() - t0 < WINDOW


def strike(ip):
    now = time.time()
    count, t0 = FAILS.get(ip, (0, now))
    FAILS[ip] = (1, now) if now - t0 >= WINDOW else (count + 1, t0)
    if len(FAILS) > 1000:  # forget expired entries so rotating addresses can't grow this forever
        for k in [k for k, (_, t) in FAILS.items() if now - t >= WINDOW]:
            del FAILS[k]


def load_tokens():
    """[(friend, token)] from TOKENS_FILE. Re-read on every upload, so adding or revoking a friend needs no restart."""
    try:
        with open(TOKENS_FILE) as token_file:
            lines = token_file.read().splitlines()
    except OSError:
        return []
    parts = [line.split() for line in lines]
    return [(p[0], p[1]) for p in parts if len(p) == 2 and re.fullmatch(NAME, p[0]) and len(p[1]) >= 16]


def add(name, url="https://YOUR-DOMAIN"):
    if not re.fullmatch(NAME, name):
        sys.exit("NAME: letters, digits, _ . - (max 32)")
    if name in [n for n, _ in load_tokens()]:
        sys.exit(f"{name} already has a token; delete its line in {TOKENS_FILE} to issue a new one")
    token = secrets.token_urlsafe(24)
    with os.fdopen(os.open(TOKENS_FILE, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600), "a") as f:
        f.write(f"{name} {token}\n")
    print(f"Send this to {name} privately. They merge it into ~/.claude/settings.json and restart Claude Code:", file=sys.stderr)
    print(json.dumps({"env": {
        **telemetry.EXTRA_ENV, "CLAUDE_CODE_ENABLE_TELEMETRY": "1", "OTEL_METRICS_EXPORTER": "otlp", "OTEL_EXPORTER_OTLP_PROTOCOL": "http/json",
        "OTEL_EXPORTER_OTLP_ENDPOINT": url, "OTEL_EXPORTER_OTLP_HEADERS": f"Authorization=Bearer {token}"}}, indent=2))


def connect():
    db = sqlite3.connect(DB)
    db.execute(SCHEMA)
    with db:
        telemetry.initialize(db)
    return db


cap = lambda s, k: None if s is None else str(s)[:k]


def attrs(kvs):
    return {kv["key"]: next(iter(kv["value"].values()), None) for kv in kvs or []}


def ingest(db, payload, friend):
    telemetry.ingest(db, payload, friend, 'metrics')


# ---- data ----------------------------------------------------------------------------------------------------------

n = lambda v: f"{(v or 0):,.0f}"
usd = lambda v: f"${(v or 0):.2f}"
TOK = "metric='token.usage'"
# tokens, input, output, cache, cost, sessions, active minutes
AGG = f"""SUM(CASE WHEN {TOK} THEN value END),
    SUM(CASE WHEN {TOK} AND type='input' THEN value END),
    SUM(CASE WHEN {TOK} AND type='output' THEN value END),
    SUM(CASE WHEN {TOK} AND type LIKE 'cache%' THEN value END),
    SUM(CASE WHEN metric='cost.usage' THEN value END),
    SUM(CASE WHEN metric='session.count' THEN value END),
    SUM(CASE WHEN metric='active_time.total' THEN value END) / 60"""
fmt = lambda v: (*map(n, v[:4]), usd(v[4]), n(v[5]), n(v[6]))  # formats an AGG slice
SUM_HEAD = ["tokens all", "input", "output", "cache", "est. cost", "sessions", "active min"]
# range -> (label, tokens column, cost column) in summary() rows
RANGES = {"today": ("Today", 1, 3), "7d": ("7 days", 2, 4), "all": ("All time", 5, 9)}


def summary(db):
    """One row per friend: name, tokens today, tokens 7d, cost today, cost 7d, then AGG (all time)."""
    day0 = int(time.time()) // 86400 * 86400
    return db.execute(f"""SELECT friend,
        SUM(CASE WHEN {TOK} AND ts>=:d THEN value END), SUM(CASE WHEN {TOK} AND ts>=:w THEN value END),
        SUM(CASE WHEN metric='cost.usage' AND ts>=:d THEN value END), SUM(CASE WHEN metric='cost.usage' AND ts>=:w THEN value END),
        {AGG} FROM points GROUP BY friend""", {"d": day0, "w": day0 - 6 * 86400}).fetchall()


# ---- html helpers --------------------------------------------------------------------------------------------------

class Safe(str):
    """Pre-escaped HTML cell."""


def tbl(head, rows):
    cell = lambda c: c if isinstance(c, Safe) else html.escape(str(c))
    th = "".join(f"<th>{h}</th>" for h in head)
    tr = "".join("<tr>" + "".join(f"<td>{cell(c)}</td>" for c in r) + "</tr>" for r in rows)
    return f'<div class="tw"><table><tr>{th}</tr>{tr}</table></div>'


def short(v):
    v = v or 0
    for lim, suf in ((1e6, "M"), (1e3, "k")):
        if v >= lim:
            x = v / lim
            return f"{x:.1f}{suf}" if x < 10 else f"{x:.0f}{suf}"
    return n(v)


def dur(minutes):
    m = int(round(minutes or 0))
    return f"{m // 60}h {m % 60}m" if m >= 60 else f"{m}m"


hue = lambda name: int(hashlib.md5(name.encode()).hexdigest()[:4], 16) % 360


def bib(name, size=40):
    """Race bib avatar: friend's colour, four safety pins, their initial."""
    ini = html.escape(name.strip()[:1].upper() or "?")
    pins = "".join(f'<circle cx="{x}" cy="{y}" r="1.8"/>' for x in (4, 46) for y in (4, 36))
    return (f'<svg class="bib" width="{size}" height="{size * 4 // 5}" viewBox="0 0 50 40" aria-hidden="true">'
            f'<rect x="1" y="1" width="48" height="38" rx="3" fill="hsl({hue(name)} 65% 38%)" stroke="#fff" stroke-width="1.5"/>'
            f'<g fill="#fff" fill-opacity=".8">{pins}</g>'
            '<text x="25" y="30" text-anchor="middle" font-size="26" font-weight="800" fill="#fff" '
            f'font-family="Big Shoulders Display,Arial Narrow,Impact,sans-serif">{ini}</text></svg>')


FONT_FILES = {}  # filename -> bytes, filled at startup from ./fonts (self-hosted: no third-party requests)

STYLE = """
@font-face{font-family:Archivo;src:url(/fonts/archivo.woff2) format("woff2");font-weight:400 600;font-display:swap}
@font-face{font-family:"Big Shoulders Display";src:url(/fonts/bigshoulders.woff2) format("woff2");font-weight:700 800;font-display:swap}
:root{--chalk:#F2F4F1;--ink:#13223A;--track:#2457A8;--mark:#F7C948;--muted:#5B6A80;--rule:#13223A22;
  --c-cache:#B9C6DA;--c-in:#6C93CF;--c-out:#13223A;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--chalk:#0E1A2E;--ink:#E8EDF4;--muted:#9AA9BF;--rule:#E8EDF422;
  --c-cache:#3B4D6B;--c-in:#6C93CF;--c-out:#F2F4F1}}
*{box-sizing:border-box}
body{margin:0;background:var(--chalk);color:var(--ink);font:15px/1.5 Archivo,system-ui,sans-serif}
main{max-width:56rem;margin:0 auto;padding:1.5rem 16px 4rem}
h1,h2,.name,.val,.rank,dd{font-family:"Big Shoulders Display","Arial Narrow",Impact,sans-serif;font-variant-numeric:tabular-nums}
h1{font-size:clamp(2rem,6vw,3.5rem);line-height:1;margin:0;font-weight:800}
h2{font-size:1.75rem;margin:2.5rem 0 .5rem;font-weight:700}
a{color:inherit}
.note{color:var(--muted);margin:.5rem 0 0}
a:focus-visible,input:focus-visible,button:focus-visible{outline:3px solid var(--track);outline-offset:2px}

.top{display:flex;flex-wrap:wrap;gap:1rem;align-items:flex-end;justify-content:space-between}
.range{display:flex;flex-wrap:wrap;gap:.25rem}
.range a{padding:.35rem .9rem;border-radius:999px;text-decoration:none;border:1px solid var(--rule)}
.range a[aria-current=page]{background:var(--mark);border-color:var(--mark);color:#13223A;font-weight:600}

.track{background:var(--track);color:#fff;border-radius:8px;margin:1.25rem 0;overflow:hidden}
.lane{display:grid;grid-template-columns:2rem 44px 7rem 1fr 7.5rem;align-items:center;gap:.75rem;
  padding:.9rem 1rem;color:#fff;text-decoration:none}
.lane+.lane{border-top:2px dashed #ffffff80}
.lane:hover{background:#ffffff1f}
.lane:focus-visible{outline:3px solid var(--mark);outline-offset:-3px}
.rank{font-size:1.75rem;font-weight:800;opacity:.85}
.bib{display:block}
.name{font-size:1.5rem;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.run{display:block;height:1.6rem;border-right:5px solid var(--mark)}
.bar{display:block;width:var(--w);min-width:6px;height:100%;border:2px solid #fff;border-radius:0 999px 999px 0;
  background:hsl(var(--h) 85% 62%);transform-origin:left;
  animation:run .9s cubic-bezier(.2,.7,.2,1) calc(var(--i) * 120ms) both}
.val{font-size:1.5rem;font-weight:700;text-align:right;animation:fade .4s calc(var(--i) * 120ms + .7s) both}
.val small{display:block;font:400 .8rem Archivo,system-ui,sans-serif;opacity:.85}
@keyframes run{from{transform:scaleX(0)}}
@keyframes fade{from{opacity:0}}
.empty{margin:0;padding:2rem 1rem;max-width:40rem}

.tw{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
th,td{padding:.5rem .75rem;text-align:right;white-space:nowrap;border-bottom:1px solid var(--rule)}
th{font-weight:600;font-size:.85rem;color:var(--muted)}
th:first-child,td:first-child{text-align:left}

.who{display:flex;align-items:center;gap:1.25rem;margin:1rem 0 1.5rem}
.who p{margin:.25rem 0 0;color:var(--muted)}
.splits{display:flex;flex-wrap:wrap;gap:0 2rem;margin:0;border-top:3px solid var(--mark)}
.splits div{padding:.75rem 0;min-width:5.5rem}
.splits dt{font-size:.85rem;color:var(--muted)}
.splits dd{margin:0;font-size:2rem;font-weight:700;line-height:1.1}
.s-cache{background:var(--c-cache);fill:var(--c-cache)}
.s-in{background:var(--c-in);fill:var(--c-in)}
.s-out{background:var(--c-out);fill:var(--c-out)}
.mix{display:flex;height:1.5rem;border-radius:4px;overflow:hidden;margin:.5rem 0}
.legend{display:flex;flex-wrap:wrap;gap:.25rem 1.25rem;margin:0;padding:0;list-style:none}
.legend i{display:inline-block;width:.8rem;height:.8rem;border-radius:2px;margin-right:.4rem}
.chartwrap{overflow-x:auto}
.chart{display:block;width:100%;min-width:480px;height:auto}
.chart text{fill:var(--muted);font:11px Archivo,system-ui,sans-serif}
.chart .base{stroke:var(--rule)}
.chart .stub{fill:var(--muted);opacity:.35}
.col{transform-origin:50% 100%;transform-box:fill-box;animation:rise .6s cubic-bezier(.2,.7,.2,1) calc(var(--i) * 20ms) both}
@keyframes rise{from{transform:scaleY(0)}}

.login{display:flex;gap:.5rem;margin-top:1rem;max-width:26rem}
.login input{flex:1;padding:.6rem .8rem;font:inherit;color:inherit;background:transparent;border:1px solid var(--rule);border-radius:6px}
.login button{padding:.6rem 1rem;font:inherit;font-weight:600;background:var(--mark);color:#13223A;border:0;border-radius:6px;cursor:pointer}
@media (max-width:600px){
  .lane{grid-template-columns:1.5rem 36px 1fr auto;grid-template-areas:"rank bib name val" "run run run run";gap:.5rem .75rem}
  .rank{grid-area:rank}.bib{grid-area:bib}.name{grid-area:name}.val{grid-area:val}.run{grid-area:run}
}
@media (prefers-reduced-motion:reduce){.bar,.val,.col{animation:none}}
"""

STYLE += """
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:1rem;margin:1.5rem 0}
.card{border:1px solid var(--rule);border-radius:12px;padding:1rem;background:var(--rule)}
.card strong{font-size:1.5rem;display:block}.card p{margin:.5rem 0 0}
.badge{display:inline-block;font-size:.75rem;border:1px solid var(--rule);border-radius:99px;padding:.15rem .5rem}
.daily-chart{margin:1rem 0;border:1px solid var(--rule);border-radius:12px;padding:1rem}
.day-bars{display:flex;align-items:stretch;height:180px;gap:3px}
.day-button{flex:1;min-width:0;display:flex;flex-direction:column;justify-content:flex-end;padding:0 2px 0;border:0;border-bottom:2px solid var(--rule);background:transparent;cursor:pointer;color:var(--ink)}
.day-button span{display:block;width:100%;min-height:0;pointer-events:none}
.day-button:hover,.day-button[aria-pressed=true]{background:var(--rule);outline:2px solid var(--mark);outline-offset:1px}
.day-button .zero{height:2px;background:var(--muted)}
.day-details{white-space:pre-line;min-height:7.5rem;margin:1rem 0 0;padding:1rem;background:var(--rule);border-radius:8px;font-variant-numeric:tabular-nums}
.axis{display:flex;justify-content:space-between;color:var(--muted);font-size:.8rem;margin-top:.5rem}
summary{cursor:pointer;font-weight:600;padding:1rem 0}
"""


def start_for(rng):
    day0 = int(time.time()) // 86400 * 86400
    return day0 if rng == "today" else day0 - 6 * 86400 if rng == "7d" else 0


def range_nav(rng, friend=None):
    base = "/?" if friend is None else "/friend?name=" + quote(friend) + "&amp;"
    return '<nav class="range" aria-label="Date range">' + ''.join(
        f'<a href="{base}range={key}"' + (' aria-current="page"' if key == rng else '') + f'>{value[0]}</a>'
        for key, value in RANGES.items()) + '</nav>'


def coverage(db, friend=None, rng="7d"):
    where, args = ("AND friend=?", (start_for(rng), friend)) if friend else ("", (start_for(rng),))
    total = db.execute(f"SELECT SUM(value) FROM points WHERE metric='token.usage' AND ts>=? {where}", args).fetchone()[0]
    last = db.execute("SELECT MAX(ts) FROM points" + (" WHERE friend=?" if friend else ""), (friend,) if friend else ()).fetchone()[0]
    stamp = time.strftime('%d %b %Y, %H:%M UTC', time.gmtime(last)) if last else 'No metrics received'
    return (f'<section class="cards" aria-label="Usage coverage"><div class="card"><span class="badge">Measured · {RANGES[rng][0]}</span>'
            f'<p>Claude Code</p><strong>{n(total)} tokens</strong><p class="note">Last recorded activity: {stamp}</p></div>'
            '<div class="card"><span class="badge">Not connected</span><p>Claude Design · web &amp; app</p>'
            '<strong>Unavailable</strong><p class="note">Design tokens are not included in this collector. Unavailable does not mean zero usage.</p></div></section>')


def daily_chart(days, rng, dates=None, unit='day'):
    """One button per key in `dates` (default: the last 1/7/30 UTC days). Hourly use passes dates=['00:00', ...]."""
    day0 = int(time.time()) // 86400 * 86400
    count = 1 if rng == 'today' else 7 if rng == '7d' else 30
    by = {r[0]: r for r in days}
    dates = dates or [time.strftime('%Y-%m-%d', time.gmtime(day0-i*86400)) for i in range(count-1,-1,-1)]
    top = max([sum((r[i] or 0) for i in (2,3,4)) for r in days if r[0] in dates] + [1])
    buttons = []
    for date in dates:
        r = by.get(date, (date,0,0,0,0,0,0,0))
        info = (f'{date} · UTC\n{n(r[1])} total tokens · {usd(r[5])} estimated cost\n'
                f'Input {n(r[2])} · Output {n(r[3])} · Cache {n(r[4])}\n'
                f'Sessions {n(r[6])} · Active {dur(r[7])}') if date in by else f'{date} · UTC\nNo telemetry recorded for this {unit}.'
        stack = ''.join(f'<span class="s-{c}" style="height:{160*(v or 0)/top:.2f}px"></span>'
                        for v,c in ((r[3],'out'),(r[2],'in'),(r[4],'cache')))
        if not r[1]: stack = '<span class="zero"></span>'
        buttons.append(f'<button type="button" class="day-button" aria-pressed="false" aria-label="{html.escape(info, quote=True)}" data-details="{html.escape(info, quote=True)}">{stack}</button>')
    return (f'<div class="daily-chart"><p class="note">Hover, tap, or focus a {unit} for exact values. Use arrow keys to move between {unit}s.</p>'
            + '<div class="day-bars">'+''.join(buttons)+'</div>'
            +f'<div class="axis"><span>{dates[0]}</span><span>{dates[-1]} · UTC</span></div>'
            +f'<p class="day-details" role="status" aria-live="polite">Select a {unit} to inspect tokens, cost, sessions, and active time.</p></div>')



HOURS = [f"{h:02}:00" for h in range(24)]


def hourly_rows(db, friend, rng):
    """Detail-page rows shaped like the daily ones: ('07:00', *AGG). UTC hour of day, summed over the range."""
    return db.execute(f"SELECT strftime('%H:00',ts,'unixepoch') AS h, {AGG} FROM points WHERE friend=? AND ts>=? AND ts>0 GROUP BY h",
                      (friend, start_for(rng))).fetchall()


def hourly_table(db, rng):
    """Home page: one row per member, 24 UTC hour columns of tokens, shaded by share of the busiest cell."""
    grid = {(f, h): v for f, h, v in db.execute(
        f"SELECT friend, strftime('%H:00',ts,'unixepoch'), SUM(value) FROM points WHERE {TOK} AND ts>=? AND ts>0 GROUP BY 1,2", (start_for(rng),))}
    peak = max(list(grid.values()) + [1])
    members = sorted({f for f, _ in grid}, key=lambda f: -sum(v for (g, _), v in grid.items() if g == f))
    cell = lambda f, h: Safe(f'<span title="{html.escape(f)} {h} UTC: {n(grid.get((f, h)))} tokens" style="display:block;padding:.1rem .3rem;border-radius:4px;'
                             f'background:rgba(80,140,210,{.08 + .75 * grid.get((f, h), 0) / peak:.2f})">{short(grid[f, h]) if (f, h) in grid else "·"}</span>')
    return tbl(["UTC hour"] + [h[:2] for h in HOURS], [(link(f), *(cell(f, h) for h in HOURS)) for f in members])


def layout(title, body):
    return ("<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title><link rel=icon href=data:,>"
            + "<style>" + STYLE + telemetry.STYLE + "</style><main>" + ('<p><a href="/">Usage</a> · <a href="/explore">Explore all telemetry</a></p>' if title != "Sign in" else "") + body + "</main><script>" + UI_SCRIPT + "</script>")


NOTE = '<p class="note">Days are UTC. Cost is an API-price estimate, not what Pro charges.</p>'
link = lambda f: Safe(f'<a href="/friend?name={quote(f)}">{html.escape(f)}</a>')


# ---- pages ---------------------------------------------------------------------------------------------------------

def lanes(rows, rng):
    _, vi, ci = RANGES[rng]
    ranked = sorted(rows, key=lambda r: -(r[vi] or 0))
    lead = max(ranked[0][vi] or 0, 1)
    return "".join(
        f'<a class="lane" href="/friend?name={quote(r[0])}" style="--i:{i};--w:{100 * (r[vi] or 0) / lead:.1f}%;--h:{hue(r[0])}" '
        f'aria-label="{html.escape(r[0])}, rank {i + 1}, {n(r[vi])} tokens">'
        f'<span class="rank">{i + 1}</span>{bib(r[0], 44)}<span class="name">{html.escape(r[0])}</span>'
        f'<span class="run"><span class="bar"></span></span>'
        f'<span class="val">{short(r[vi])}<small>{usd(r[ci])}</small></span></a>'
        for i, r in enumerate(ranked))


def home(db, rng="7d"):
    rows = summary(db)
    switch = "".join(f'<a href="/?range={k}"{" aria-current=page" if k == rng else ""}>{v[0]}</a>' for k, v in RANGES.items())
    body = f'<header class="top"><h1>Who&rsquo;s using the Pro account</h1><nav class="range">{switch}</nav></header>' + NOTE
    if not rows:
        return layout("Claude usage", body + coverage(db, rng=rng) + '<div class="track"><p class="empty">No one on the track yet. Add the telemetry settings to a '
                      "friend's Claude Code and they'll show up here after their first prompt.</p></div>")
    return layout("Claude usage", body + coverage(db, rng=rng) + f'<div class="track">{lanes(rows, rng)}</div><h2>Full breakdown · {RANGES[rng][0]}</h2>'
                  + tbl(["friend"] + SUM_HEAD, [(link(r[0]), *fmt(r[1:])) for r in db.execute(
                      f"SELECT friend, {AGG} FROM points WHERE ts>=? GROUP BY friend ORDER BY 2 DESC", (start_for(rng),))])
                  + f"<h2>Hourly breakdown · {RANGES[rng][0]} · UTC</h2>" + hourly_table(db, rng))


def mix(r):
    parts = [("cache", "cache", r[8]), ("in", "input", r[6]), ("out", "output", r[7])]
    total = sum(v or 0 for *_, v in parts) or 1
    bar = "".join(f'<span class="s-{c}" style="width:{100 * (v or 0) / total:.2f}%"></span>' for c, _, v in parts)
    key = "".join(f'<li><i class="s-{c}"></i>{label} {short(v)} ({100 * (v or 0) / total:.0f}%)</li>' for c, label, v in parts)
    return f'<div class="mix" aria-hidden="true">{bar}</div><ul class="legend">{key}</ul>'


def chart(days):
    """30 columns, one per UTC day, stacked cache/input/output. days rows: date, tokens, input, output, cache, cost, ..."""
    day0 = int(time.time()) // 86400 * 86400
    by = {d[0]: d for d in days}
    span = [time.gmtime(day0 - i * 86400) for i in range(29, -1, -1)]
    top = max([(d[2] or 0) + (d[3] or 0) + (d[4] or 0) for d in days] + [1])
    cols, labels = [], []
    for k, g in enumerate(span):
        x, date, label = k * 20 + 3, time.strftime("%Y-%m-%d", g), time.strftime("%b %d", g)
        if k % 7 == 0:
            labels.append(f'<text x="{x}" y="153">{label}</text>')
        r = by.get(date)
        parts = [(r[4] or 0, "cache"), (r[2] or 0, "in"), (r[3] or 0, "out")] if r else []
        total = sum(v for v, _ in parts)
        if not total:
            cols.append(f'<rect class="stub" x="{x}" y="133" width="14" height="2"/>')
            continue
        y, rects = 135.0, ""
        for v, c in parts:
            h = 130 * v / top
            y -= h
            rects += f'<rect class="s-{c}" x="{x}" y="{y:.1f}" width="14" height="{h:.1f}"/>'
        cols.append(f'<g><title>{label}: {n(total)} tokens, {usd(r[5])}</title>'
                    f'<rect x="{k * 20}" y="0" width="20" height="135" fill="transparent"/>'
                    f'<g class="col" style="--i:{k}">{rects}</g></g>')
    return ('<div class="chartwrap"><svg class="chart" viewBox="0 0 600 160" role="img" aria-label="Tokens per day, last 30 days">'
            '<line class="base" x1="0" x2="600" y1="135" y2="135"/>' + "".join(cols) + "".join(labels) + "</svg></div>")


def detail(db, friend, rng="all"):
    rows = summary(db)
    r = next((r for r in rows if r[0] == friend), None)
    if r is None:
        return None
    rank = [x[0] for x in sorted(rows, key=lambda x: -(x[2] or 0))].index(friend) + 1
    day0 = int(time.time()) // 86400 * 86400
    days = db.execute(f"""SELECT date(ts,'unixepoch') AS d, {AGG} FROM points
        WHERE friend=? AND ts>=? GROUP BY d""", (friend, day0 - 29 * 86400)).fetchall()
    models = db.execute(f"""SELECT model, SUM(CASE WHEN {TOK} THEN value END), SUM(CASE WHEN metric='cost.usage' THEN value END)
        FROM points WHERE friend=? AND model IS NOT NULL GROUP BY model ORDER BY 2 DESC""", (friend,)).fetchall()
    period = db.execute(f"SELECT {AGG} FROM points WHERE friend=? AND ts>=?", (friend, start_for(rng))).fetchone()
    cache = db.execute("SELECT type, SUM(value) FROM points WHERE friend=? AND ts>=? AND metric='token.usage' GROUP BY type ORDER BY 2 DESC", (friend, start_for(rng))).fetchall()
    models = db.execute(f"SELECT model, {AGG} FROM points WHERE friend=? AND ts>=? GROUP BY model ORDER BY 2 DESC", (friend, start_for(rng))).fetchall()
    stat = lambda label, v: f"<div><dt>{label}</dt><dd>{v}</dd></div>"
    splits = "".join([stat("Today", short(r[1])), stat("7 days", short(r[2])), stat("All time", short(r[5])), stat("All-time est. cost", usd(r[9])),
                      stat("All-time sessions", n(r[10])), stat("All-time active", dur(r[11]))])
    return layout(friend, f'<p><a href="/">All members</a></p>'
                  f'<div class="who">{bib(friend, 72)}<div><h1>{html.escape(friend)}</h1><p>Rank {rank} of {len(rows)} over the last 7 days</p></div></div>'
                  f'<dl class="splits">{splits}</dl>' + NOTE + range_nav(rng, friend) + coverage(db, friend, rng)
                  + f"<h2>Token mix · {RANGES[rng][0]}</h2>" + mix((friend,0,0,0,0,*period))
                  + tbl(["Token type", "Tokens"], [( {"input":"Input (uncached)", "output":"Output", "cacheRead":"Cache read", "cacheCreation":"Cache write"}.get(t, t or "Unspecified"), n(v)) for t,v in cache])
                  + ("<h2>Last 30 days</h2>" if rng == "all" else f"<h2>Daily usage · {RANGES[rng][0]}</h2>") + daily_chart(days, rng)
                  + f"<h2>Hourly usage · {RANGES[rng][0]} · UTC</h2>" + daily_chart(hourly_rows(db, friend, rng), rng, HOURS, "hour")
                  + "<details><summary>Daily values · last 30 days</summary>" + tbl(["UTC date"]+SUM_HEAD, [(d[0], *fmt(d[1:])) for d in reversed(sorted(days))]) + "</details>"
                  + f"<h2>By model · {RANGES[rng][0]}</h2>" + tbl(["model"]+SUM_HEAD[:5], [(m[0] or "Unspecified", *fmt(m[1:])[:5]) for m in models]) + telemetry.usage_summary(db, friend))


LOGIN = layout("Sign in", '<h1>Claude Code usage</h1><p class="note">Enter the dashboard password.</p>'
               '<form class="login" method="post" action="/login"><input name="key" type="password" placeholder="Password" '
               'aria-label="Password" autofocus>'
               "<button>Open dashboard</button></form>")


class H(BaseHTTPRequestHandler):
    timeout = 15  # drop stalled connections (slowloris)
    server_version, sys_version = "usage", ""

    def send(self, code, body=b"{}", ctype="application/json", headers=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in {**dict(SEC_HEADERS), **dict(headers)}.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def html(self, code, body, headers=()):
        self.send(code, body.encode(), "text/html; charset=utf-8", headers)

    def read(self, limit):
        """Request body, or None if Content-Length is missing, negative, junk or over the limit."""
        try:
            n = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return None
        return self.rfile.read(n) if 0 <= n <= limit else None

    def ip(self):
        return self.headers.get("X-Forwarded-For", "").split(",")[-1].strip() or self.client_address[0]  # last hop = Caddy

    def fail(self, what):  # shows brute-force attempts in journald; never logs the secret itself
        ip = self.ip()
        strike(ip)
        sys.stderr.write(f"{what} from {ip}\n")

    def do_POST(self):
        path = urlparse(self.path).path
        if path not in ("/v1/metrics", "/v1/logs", "/v1/traces", "/login", "/usage"):
            return self.send(404)
        if blocked(self.ip()):
            return self.send(429, headers=[("Retry-After", str(WINDOW))])
        if path == "/usage":  # dashboard-only form; SameSite=Strict session cookie stops cross-site posts
            jar = dict(p.strip().partition("=")[::2] for p in self.headers.get("Cookie", "").split(";"))
            if not same(jar.get("session", ""), session()):
                return self.html(401, LOGIN)
            form = parse_qs((self.read(4096) or b"").decode("utf-8", "replace"))
            try:
                with closing(connect()) as db, db:
                    telemetry.add_snapshot(db, form.get("friend", [""])[0], form.get("label", [""])[0], form.get("pct", [""])[0], form.get("note", [""])[0])
            except ValueError:
                return self.html(400, layout("Invalid reading", '<p>Pick a reading and a percentage from 0 to 100. <a href="/explore?tab=usage">Back</a></p>'))
            return self.send(303, b"", "text/plain", [("Location", "/explore?tab=usage")])
        if path.startswith("/v1/"):
            given, friend = bearer(self.headers.get("Authorization", "")), None
            for name, token in load_tokens():  # no early exit
                if same(given, token):
                    friend = name
            if friend is None:
                self.fail("bad upload token")
                return self.send(401)
            if os.path.exists(DB) and os.path.getsize(DB) > MAX_DB:
                return self.send(507)
            raw = self.read(MAX_BODY)
            try:
                if raw is None:
                    raise ValueError("bad Content-Length")
                if self.headers.get("Content-Encoding") == "gzip":
                    raw = unzip(raw)
                with closing(connect()) as db, db:
                    telemetry.ingest(db, json.loads(raw), friend, path.rsplit("/", 1)[-1])
            except sqlite3.OperationalError:  # e.g. database locked: exporter retries later
                return self.send(503)
            except (ValueError, KeyError, TypeError, AttributeError, OverflowError, OSError, zlib.error):
                return self.send(400)
            return self.send(200)
        raw = self.read(4096)  # /login
        key = parse_qs((raw or b"").decode("utf-8", "replace")).get("key", [""])[0]
        if not same(key, VIEW_KEY):
            self.fail("bad dashboard key")
            return self.html(401, LOGIN)
        secure = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""  # Caddy sets it
        return self.send(303, b"", "text/plain", [
            ("Location", "/"), ("Set-Cookie", f"session={session()}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000{secure}")])

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path.startswith("/fonts/"):  # public on purpose (the sign-in page needs them); only names loaded from ./fonts
            data = FONT_FILES.get(u.path[7:])
            return self.send(200, data, "font/woff2", [("Cache-Control", "public, max-age=31536000, immutable")]) if data else self.send(404)
        jar = dict(p.strip().partition("=")[::2] for p in self.headers.get("Cookie", "").split(";"))
        if not same(jar.get("session", ""), session()):
            return self.html(401, LOGIN)
        with closing(connect()) as db:
            if u.path == "/explore":
                try:
                    if q.get("format", [""])[0] == "ndjson":
                        telemetry.filters(telemetry.params(q))
                        self.send_response(200)
                        for k,v in SEC_HEADERS:
                            self.send_header(k,v)
                        self.send_header("Content-Type", "application/x-ndjson")
                        self.send_header("Content-Disposition", 'attachment; filename="telemetry-all.ndjson"')
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.close_connection = True
                        for chunk in telemetry.export_all(db,q):
                            self.wfile.write(chunk)
                        return
                    if q.get("format", [""])[0] in ("json", "csv"):
                        data, ctype, filename, nxt = telemetry.export_page(db, q)
                        headers = [("Content-Disposition", f'attachment; filename="{filename}"')]
                        if nxt:
                            headers.append(("Link", f'<{nxt}>; rel="next"'))
                        return self.send(200, data, ctype, headers)
                    return self.html(200, layout("Telemetry explorer", telemetry.page(db, q)))
                except (ValueError, OverflowError):
                    return self.html(400, layout("Invalid filters", "<p>Check the dates and page number in your filters.</p>"))
            if u.path == "/":
                rng = q.get("range", ["7d"])[0]
                return self.html(200, home(db, rng if rng in RANGES else "7d"))
            if u.path == "/friend":
                rng = q.get("range", ["all"])[0]
                body = detail(db, q.get("name", [""])[0], rng if rng in RANGES else "all")
                return self.html(200, body) if body else self.html(404, layout("Not found", '<p>No such member. <a href="/">All members</a></p>'))
        self.send(404)

    def log_message(self, *a):  # default log would print request paths
        pass


def check():
    import tempfile
    global VIEW_KEY, TOKENS_FILE
    now = str(int(time.time() * 1e9))
    dp = lambda v, **kw: {
        "asInt" if isinstance(v, int) else "asDouble": str(v) if isinstance(v, int) else v, "timeUnixNano": now,
        "attributes": [{"key": k, "value": {"stringValue": x}} for k, x in kw.items()]}
    metric = lambda name, *dps: {"name": "claude_code." + name, "sum": {"dataPoints": list(dps)}}
    wrap = lambda *metrics: {"resourceMetrics": [{"scopeMetrics": [{"metrics": list(metrics)}]}]}
    db = sqlite3.connect(":memory:")
    db.execute(SCHEMA)
    ingest(db, wrap(metric("token.usage", dp(100, type="input", model="m", **{"friend.name": "evil"}), dp(50.0, type="output", model="m")),
                    metric("cost.usage", dp(0.5, model="m")), metric("lines_of_code.count", dp(9))), "rahul")
    ingest(db, wrap(metric("token.usage", dp(7, type="input"))), "asha")
    db.execute("INSERT INTO points VALUES(?,?,?,?,?,?)", (int(time.time()), "<b>x", "session.count", None, None, 1.0))
    got = dict(db.execute("SELECT friend, SUM(value) FROM points WHERE metric='token.usage' GROUP BY friend"))
    assert got == {"rahul": 150.0, "asha": 7.0}, got  # the name comes from the token, not the payload
    assert db.execute("SELECT COUNT(*) FROM points").fetchone()[0] == 6  # all numeric sum metrics retained

    out = home(db)  # lanes are ranked and escaped
    assert out.index("name=rahul") < out.index("name=asha")
    assert "&lt;b&gt;x" in out and "<b>x" not in out and 'class="bib"' in out and "Hourly breakdown" in out
    db.execute("INSERT INTO points VALUES(?,?,?,?,?,?)", (int(time.time()) - 20 * 86400, "oldie", "token.usage", "input", "m", 10000.0))
    assert home(db, "all").index("name=oldie") < home(db, "all").index("name=rahul")  # range re-ranks
    assert home(db, "today").index("name=rahul") < home(db, "today").index("name=oldie")
    empty = sqlite3.connect(":memory:")
    empty.execute(SCHEMA)
    assert "No one on the track yet" in home(empty)

    d = detail(db, "rahul")
    assert d.count('class="day-button"') == 30 + 24 and "Hourly usage" in d
    assert "All members" in d and "$0.50" in d and "150" in d and ">m<" in d and "Rank 1 of" in d
    assert "150 total tokens" in d and "data-details=" in d and "Unavailable" in d
    assert "&lt;b&gt;x" in detail(db, "<b>x") and detail(db, "nobody") is None

    ingest(db, wrap(metric("token.usage", dp(-5, type="input"), dp(float("nan"), type="input"), dp(float("inf"), type="input"),
                           dp(3, type="input", model="z" * 500))), "capcheck")  # negative/NaN/inf dropped, long model cut
    assert db.execute("SELECT MAX(LENGTH(model)), COUNT(*) FROM points WHERE friend='capcheck'").fetchone() == (64, 1)

    VIEW_KEY = "dashboard-password-123"
    assert session() == session() and VIEW_KEY not in session() and len(session()) == 64
    assert same("a", "a") and not same("a", "b") and not same("a", "") and not same("", "")
    assert bearer("Bearer t") == "t" and bearer("t") == "" and bearer("") == ""
    z = zlib.compressobj(wbits=31)
    assert unzip(z.compress(b'{"a":1}') + z.flush()) == b'{"a":1}'
    z = zlib.compressobj(wbits=31)
    try:
        unzip(z.compress(b"0" * (MAX_BODY + 1)) + z.flush())
        raise AssertionError("gzip bomb accepted")
    except ValueError:
        pass

    with tempfile.TemporaryDirectory() as tmp:  # tokens file: comments, bad names and short tokens are ignored
        TOKENS_FILE = os.path.join(tmp, "tokens.txt")
        assert load_tokens() == []
        open(TOKENS_FILE, "w").write("# c\nrahul " + "a" * 24 + "\nbad!name " + "b" * 24 + "\nshort abc\nasha " + "c" * 24 + "\n\nthree parts here\n")
        assert [n for n, _ in load_tokens()] == ["rahul", "asha"]
    FAILS.clear()  # 5 strikes block one address for the window, then it resets
    for _ in range(LIMIT):
        strike("1.2.3.4")
    assert blocked("1.2.3.4") and not blocked("5.6.7.8")
    FAILS["1.2.3.4"] = (LIMIT, time.time() - WINDOW - 1)
    assert not blocked("1.2.3.4")
    strike("1.2.3.4")
    assert FAILS["1.2.3.4"][0] == 1
    assert 'method="post"' in LOGIN and "Open dashboard" in LOGIN and short(412_000) == "412k" and short(1_900_000) == "1.9M" and dur(200) == "3h 20m"


if __name__ == "__main__":
    if "--check" in sys.argv:
        check()
        print("ok")
    elif "--add" in sys.argv:
        args = sys.argv[sys.argv.index("--add") + 1:]
        add(*args[:2]) if args else sys.exit("usage: server.py --add NAME [https://your.domain]")
    else:
        if len(VIEW_KEY) < 16:
            sys.exit("set VIEW_KEY (at least 16 characters)")
        tokens = load_tokens()
        if not tokens:
            sys.exit(f"no tokens in {TOKENS_FILE}; create one with: python3 server.py --add NAME")
        if any(t == VIEW_KEY for _, t in tokens):
            sys.exit("VIEW_KEY must differ from every upload token")
        os.umask(0o077)  # database files readable by this user only
        connect().close()
        os.chmod(DB, 0o600)
        fonts = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts")
        for f in os.listdir(fonts) if os.path.isdir(fonts) else []:
            if f.endswith(".woff2"):
                FONT_FILES[f] = open(os.path.join(fonts, f), "rb").read()
        ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
