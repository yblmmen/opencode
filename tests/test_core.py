import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/'dashboard'))

def load(file,name):
    spec=importlib.util.spec_from_file_location(name,BASE/file)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class AnalyzeTests(unittest.TestCase):
    def setUp(self):self.a=load('scripts/lifecycle.py','pcapanalysis')
    def packet(self,t,src,sp,dst,dp,**kw):
        p={'when':t,'src':src,'sp':sp,'dst':dst,'dp':dp,'syn':False,'ack':False,'fin':False,'rst':False,
           'length':0,'tls_handshakes':[],'records':[]}
        p.update(kw);return p
    def test_observed_lifecycle(self):
        c,s='192.0.2.10','198.51.100.40'; a=self.packet
        p=[a(0,c,53001,s,443,syn=True),a(.01,s,443,c,53001,syn=True,ack=True),a(.02,c,53001,s,443,ack=True),
           a(.03,c,53001,s,443,tls_handshakes=[1],length=120),a(.04,s,443,c,53001,tls_handshakes=[2],length=200),
           a(.09,c,53001,s,443,length=400,records=[23]),a(.1,s,443,c,53001,length=200,records=[23]),
           a(.2,c,53001,s,443,fin=True,ack=True),a(.21,s,443,c,53001,fin=True,ack=True)]
        client,server,rows,missing=self.a.stages(p)
        self.assertEqual(client,(c,53001));self.assertEqual(server,(s,443))
        self.assertEqual(sum('SYN' in r['label'] for r in rows),2)
        self.assertTrue(any('TLS ClientHello' in r['label'] for r in rows))
        self.assertFalse(any('미관측' in r['label'] for r in rows))
        doc=self.a.render_svg(client,server,rows,missing)
        self.assertIn('TLS ServerHello',doc)
        self.assertNotIn('HTTP 200',doc)
    def test_no_fabricated_handshake(self):
        p=[self.packet(1,'10.0.0.1',1000,'10.0.0.2',443,length=5)]
        client,server,rows,missing=self.a.stages(p)
        self.assertFalse(rows)
        self.assertTrue(any('3-way' in x for x in missing))
    def test_tshark_parser(self):
        f=self.a.FIELDS
        d=dict.fromkeys(f,'');d.update({'frame.time_epoch':'1234567.2','ip.src':'1.2.3.4','ip.dst':'5.6.7.8','tcp.srcport':'1001','tcp.dstport':'443','tcp.len':'234','tcp.flags.syn':'1','tcp.flags.ack':'0','tls.handshake.type':'1,2'})
        event=self.a.parse_line('\t'.join(d[k] for k in f))
        self.assertTrue(event['syn']);self.assertEqual(event['tls_handshakes'],[1,2])

class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        os.environ['DB_PATH']=str(Path(self.temp.name)/'data.sqlite')
        self.s=load('dashboard/server.py','dashboardv1')
        self.s.DB_PATH=os.environ['DB_PATH']
        self.s.init_db()
    def tearDown(self): self.temp.cleanup()
    def test_metrics_and_graph(self):
        now=int(time.time())
        data={'src':'10.1.1.2','dst':'10.1.1.3','dst_port':443,'src_namespace':'frontend','dst_namespace':'backend','ts':now}
        row=self.s.validate_event(data)
        with self.s.connect() as db:
            db.execute('''INSERT INTO events (ts,src,dst,dst_port,result,bytes_in,bytes_out,duration_ms,src_namespace,dst_namespace,proto,src_port,ts_ms,tcp_flags,drop_reason,node_name,observation_point,verdict)
                          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',row)
        metrics=self.s.prometheus_metrics().decode()
        self.assertIn('opencode_hubble_flow_events_last5m{result="success"} 1',metrics)
        self.assertIn('namespace="frontend"',metrics)
        graph=self.s.grafana_graph(5)
        self.assertEqual(len(graph['edges']),1)
        self.assertEqual(len(graph['nodes']),2)
        self.assertTrue(graph['edges'][0]['source'] in {x['id'] for x in graph['nodes']})

if __name__=='__main__':unittest.main()
