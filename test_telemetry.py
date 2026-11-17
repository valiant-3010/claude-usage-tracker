import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
import telemetry as t
import server


def attrs(**kw):
    return [{'key':k,'value':{'stringValue':v}} for k,v in kw.items()]


def metric(value, ts=100, start=1, temp=1, kind='sum', name='claude_code.token.usage', **kw):
    dp={'timeUnixNano':str(ts*10**9),'startTimeUnixNano':str(start*10**9),'asDouble':value,'attributes':attrs(**kw)}
    return {'resourceMetrics':[{'resource':{'attributes':attrs(host='demo')},'scopeMetrics':[{'scope':{'name':'test'},'metrics':[{'name':name,kind:{'aggregationTemporality':temp,'isMonotonic':True,'dataPoints':[dp]}}]}]}]}


class CollectorTest(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(':memory:');self.db.execute(server.SCHEMA);t.initialize(self.db)
    def tearDown(self):self.db.close()
    def total(self):return self.db.execute('SELECT SUM(value) FROM points').fetchone()[0]
    def ingest(self,p,signal='metrics',friend='alice'):t.ingest(self.db,p,friend,signal)
    def test_retry_and_member_isolation(self):
        p=metric(10,**{'session.id':'s','model':'m'})
        self.ingest(p);self.ingest(p);self.assertEqual(self.total(),10)
        self.ingest(p,friend='bob');self.assertEqual(self.total(),20)
    def test_cumulative_late_reset(self):
        self.ingest(metric(150,ts=20,temp=2));self.ingest(metric(100,ts=10,temp=2));self.assertEqual(self.total(),150)
        self.ingest(metric(12,ts=30,start=25,temp=2));self.assertEqual(self.total(),162)
        self.ingest(metric(100,ts=10,temp=2));self.assertEqual(self.total(),162)
    def test_corrected_cumulative_sample(self):
        for v,ts in [(100,10),(150,20),(120,10)]:self.ingest(metric(v,ts=ts,temp=2))
        self.assertEqual(self.total(),150)
    def test_stream_exports_every_record(self):
        for i in range(105):self.ingest(metric(i,ts=i+1))
        self.assertEqual(sum(1 for _ in t.export_all(self.db,{})),105)
    def test_gauge_is_not_total(self):
        self.ingest(metric(30,kind='gauge'));self.assertIsNone(self.total())
        self.assertEqual(self.db.execute('SELECT value,normalized FROM telemetry_records').fetchone(),(30,None))
    def test_all_metric_types_and_nested_attrs(self):
        p=metric(10);m=p['resourceMetrics'][0]['scopeMetrics'][0]['metrics'][0]
        m['histogram']={'dataPoints':[{'timeUnixNano':'100000000000','count':'3','sum':12,'bucketCounts':['1','2'],'explicitBounds':[5]}]};del m['sum']
        self.ingest(p);raw=json.loads(self.db.execute('SELECT raw FROM telemetry_records').fetchone()[0]);self.assertEqual(raw['record']['histogram'],m['histogram'])
        self.assertEqual(t.decode({'arrayValue':{'values':[{'intValue':'2'},{'boolValue':True}]}}),[2,True])
    def test_logs_traces_fields_not_counted(self):
        log={'resourceLogs':[{'scopeLogs':[{'logRecords':[{'timeUnixNano':'100000000000','body':{'stringValue':'claude_code.api_request'},'attributes':attrs(**{'session.id':'s','duration_ms':'123','input_tokens':'99'}),'traceId':'abc','severityNumber':9}]}]}]}
        span={'resourceSpans':[{'scopeSpans':[{'spans':[{'name':'claude_code.tool','startTimeUnixNano':'100000000000','endTimeUnixNano':'101000000000','traceId':'abc','spanId':'def','events':[{'name':'output','attributes':attrs(text='hi')}],'status':{'code':1}}]}]}]}
        for _ in range(2):self.ingest(log,'logs');self.ingest(span,'traces')
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM telemetry_records').fetchone()[0],2);self.assertIsNone(self.total())
        for tab in ('overview','dimensions','records','catalog','usage','health'):
            self.assertIn('Telemetry explorer',t.page(self.db,{'tab':[tab]}))
    def test_filter_escape_export_pagination(self):
        for i in range(105):self.ingest(metric(i,ts=i+1,model='<script>alert(1)</script>'))
        page=t.page(self.db,{'tab':['records'],'key':['model'],'value':['<script>alert(1)</script>']})
        self.assertNotIn('<script>alert',page);self.assertIn('Next 100',page)
        data,_,_,nxt=t.export_page(self.db,{'format':['json']});obj=json.loads(data)
        self.assertEqual(len(obj['records']),100);self.assertTrue(nxt)
        data,_,_,nxt=t.export_page(self.db,{'format':['json'],'offset':['100']});self.assertEqual(len(json.loads(data)['records']),5);self.assertIsNone(nxt)
        self.assertIn('No records match',t.page(self.db,{'tab':['records'],'friend':["' OR 1=1 --"]}))
    def test_bad_timestamp_and_value(self):
        self.ingest(metric(float('nan')));self.assertIsNone(self.total())
        with self.assertRaises(ValueError):self.ingest(metric(2,ts=10**100))
    def test_legacy_migration_is_idempotent(self):
        db=sqlite3.connect(':memory:');db.execute(server.SCHEMA);db.execute('INSERT INTO points VALUES(1,"old","token.usage","input","m",99)')
        t.initialize(db);t.initialize(db)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM telemetry_records').fetchone()[0],1)
        self.assertEqual(db.execute('SELECT SUM(value) FROM points').fetchone()[0],99)
        self.assertIn('Original OTLP payload was not stored',db.execute('SELECT raw FROM telemetry_records').fetchone()[0]);db.close()
    def test_transaction_rollback(self):
        self.db.commit()
        with self.assertRaises(ValueError):
            with self.db:
                self.ingest(metric(10));self.ingest(metric(20,ts=10**100))
        self.assertIsNone(self.total())
    def test_manual_usage_snapshots(self):
        self.ingest(metric(1),friend='alice')
        for pct in (10,25,5):t.add_snapshot(self.db,'alice','Claude Design (weekly limit)',pct)
        t.add_snapshot(self.db,'alice','Cowork share',64)
        summary=t.usage_summary(self.db,'alice');self.assertIn('Cowork share',summary);self.assertIn('5%',summary);self.assertIn('No readings yet',t.usage_summary(self.db,'bob'))
        page=t.page(self.db,{'tab':['usage']});self.assertIn('+15.0 pts',page);self.assertIn('reset?',page)
        for bad in (('alice','nope',5),('ghost','Chats share',5),('alice','Chats share',101),('alice','Chats share','x'),('alice','Chats share',float('nan'))):
            with self.assertRaises(ValueError):t.add_snapshot(self.db,*bad)
    def test_bad_client_cannot_poison_totals(self):
        self.ingest(metric(1e300,model='m'*500,type='t'*99));self.ingest(metric(5,ts=2))
        self.assertEqual(self.total(),5)
        self.ingest(metric(7,ts=3,model='m'*500,type='t'*99))
        self.assertEqual(self.db.execute('SELECT MAX(LENGTH(model)),MAX(LENGTH(type)) FROM points').fetchone(),(64,32))
    def test_filter_validation(self):
        with self.assertRaises(ValueError):t.page(self.db,{'from':['junk']})
        with self.assertRaises(ValueError):t.page(self.db,{'offset':['bad']})



class HTTPTest(unittest.TestCase):
    def test_end_to_end(self):
        import threading
        import http.client
        old=(server.DB,server.TOKENS_FILE,server.VIEW_KEY)
        with tempfile.TemporaryDirectory() as directory:
            server.DB=str(Path(directory)/'test.db');server.TOKENS_FILE=str(Path(directory)/'tokens.txt');server.VIEW_KEY='test-password-123456'
            Path(server.TOKENS_FILE).write_text('alice upload-token-123456789\n')
            httpd=server.ThreadingHTTPServer(('127.0.0.1',0),server.H)
            thread=threading.Thread(target=httpd.serve_forever,daemon=True);thread.start()
            def request(method,path,body=None,headers=None):
                conn=http.client.HTTPConnection('127.0.0.1',httpd.server_port)
                conn.request(method,path,body,headers or {});r=conn.getresponse();result=(r.status,dict(r.getheaders()),r.read());conn.close();return result
            try:
                self.assertEqual(request('GET','/explore')[0],401)
                auth={'Authorization':'Bearer upload-token-123456789','Content-Type':'application/json'}
                p=json.dumps(metric(42,model='m'))
                self.assertEqual(request('POST','/v1/metrics',p,auth)[0],200)
                self.assertEqual(request('POST','/v1/metrics',p,auth)[0],200)
                self.assertEqual(request('POST','/v1/logs',json.dumps({'resourceLogs':[]}),auth)[0],200)
                self.assertEqual(request('POST','/v1/traces',json.dumps({'resourceSpans':[]}),auth)[0],200)
                self.assertEqual(request('POST','/v1/logs',p,auth)[0],400)
                self.assertEqual(request('GET','/explore',headers=auth)[0],401)
                status,headers,_=request('POST','/login','key=test-password-123456',{'Content-Type':'application/x-www-form-urlencoded'})
                self.assertEqual(status,303);cookie={'Cookie':headers['Set-Cookie'].split(';')[0]}
                for tab in ('overview','dimensions','records','catalog','usage','health'):
                    status,_,body=request('GET','/explore?tab='+tab,headers=cookie);self.assertEqual(status,200);self.assertIn(b'Telemetry explorer',body)
                status,_,body=request('GET','/explore?format=ndjson',headers=cookie);self.assertEqual(status,200);self.assertEqual(len(body.splitlines()),1)
                self.assertEqual(json.loads(body)['normalized'],42)
                self.assertEqual(request('GET','/explore?from=junk',headers=cookie)[0],400)
                self.assertEqual(request('GET','/',headers=cookie)[0],200)
                form={'Content-Type':'application/x-www-form-urlencoded'}
                self.assertEqual(request('POST','/usage','friend=alice&label=Chats+share&pct=7',form)[0],401)
                self.assertEqual(request('POST','/usage','friend=alice&label=Chats+share&pct=7',{**form,**cookie})[0],303)
                self.assertEqual(request('POST','/usage','friend=alice&label=Chats+share&pct=700',{**form,**cookie})[0],400)
                self.assertIn(b'Chats share',request('GET','/explore?tab=usage',headers=cookie)[2])
            finally:
                httpd.shutdown();httpd.server_close();thread.join();server.DB,server.TOKENS_FILE,server.VIEW_KEY=old

if __name__=='__main__':unittest.main()
