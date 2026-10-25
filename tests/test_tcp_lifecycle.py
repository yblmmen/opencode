import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/'dashboard'))

def loader(rel,name):
    spec=importlib.util.spec_from_file_location(name,BASE/rel)
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

A=loader('dashboard/tcp_analysis.py','tcp_v11')
C=loader('collector/collector.py','collector_v11')
S=loader('dashboard/server.py','server_v11')

class TCPTests(unittest.TestCase):
    def row(self,id,ms,src='10.0.0.1',sp=50444,dst='10.0.0.2',dp=443,flags='SYN',result='success',reason='',node='master1'):
        return dict(id=id,ts=ms//1000,ts_ms=ms,src=src,src_port=sp,dst=dst,dst_port=dp,proto='TCP',tcp_flags=flags,
                    result=result,drop_reason=reason,node_name=node,observation_point='TO_ENDPOINT')
    def test_threeway_fin_termination(self):
        n=1_700_000_000_000; r=self.row
        seq=[r(1,n),r(2,n+5,'10.0.0.2',443,'10.0.0.1',50444,'SYN,ACK'),r(3,n+8,flags='ACK'),
             r(4,n+100,flags='PSH,ACK'),r(5,n+110,flags='FIN,ACK'),
             r(6,n+120,'10.0.0.2',443,'10.0.0.1',50444,'ACK'),
             r(7,n+130,'10.0.0.2',443,'10.0.0.1',50444,'FIN,ACK'),r(8,n+140,flags='ACK')]
        self.assertEqual(len(A.sessionize(seq)),1)
        result=A.analyze(seq)
        self.assertIn('SYN / SYN+ACK / ACK 관측',result['handshake'])
        self.assertIn('양방향 FIN',result['termination'])
        self.assertEqual(result['issues'],[])
        self.assertEqual([i['found'] for i in result['stages']],[True]*7)
    def test_policy_drop_and_rst_direction(self):
        n=1_700_000_000_000; r=self.row
        seq=[r(1,n),r(2,n+25,flags='SYN',result='denied',reason='POLICY_DENIED',node='worker2'),
             r(3,n+30,'10.0.0.2',443,'10.0.0.1',50444,'RST,ACK')]
        result=A.analyze(seq)
        kinds={x['kind'] for x in result['issues']}
        self.assertIn('POLICY_DROP',kinds)
        self.assertIn('RST',kinds)
        self.assertIn('POLICY_DENIED',str(result['issues']))
        self.assertIn('서버에서 RST',str(result['issues']))
    def test_syn_repeated_no_answer(self):
        n=1_700_000_000_000; r=self.row
        d=A.analyze([r(1,n),r(2,n+1100,flags='SYN'),r(3,n+3300,flags='SYN')])
        self.assertIn('REPEATED_SYN',{x['kind'] for x in d['issues']})
    def test_split_reused_four_tuple(self):
        n=1_700_000_000_000; r=self.row
        seq=[r(1,n),r(2,n+5,'10.0.0.2',443,'10.0.0.1',50444,'SYN,ACK'),r(3,n+8,flags='ACK'),r(4,n+30000,flags='SYN')]
        self.assertEqual(len(A.sessionize(seq)),2)
    def test_flow_parser_preserves_flags_and_drop(self):
        flow={'flow': {'time':'2026-10-25T08:00:00.123456Z', 'IP':{'source':'10.1.1.1','destination':'10.1.1.2'},
              'l4':{'TCP':{'source_port':50505,'destination_port':443,'flags':{'SYN':True,'ACK':False}}},
              'source':{'namespace':'one'},'destination':{'namespace':'two'}, 'verdict':'DROPPED',
              'drop_reason_desc':'POLICY_DENIED','node_name':'worker2'}}
        d=C.flow_to_event(flow)
        self.assertEqual(d['tcp_flags'],['SYN'])
        self.assertEqual(d['drop_reason'],'POLICY_DENIED')
        self.assertEqual(d['node_name'],'worker2')
        self.assertEqual(d['ts_ms']%1000,123)
        self.assertEqual(d['result'],'denied')
    def test_db_api_support_and_backward_schema(self):
        with tempfile.TemporaryDirectory() as d:
            S.DB_PATH=str(Path(d)/'events.sqlite')
            S.init_db()
            n=int(time.time()*1000)
            src=[dict(ts=n//1000,ts_ms=n,src='10.0.0.1',src_port=50500,dst='10.0.0.2',dst_port=443,
                   proto='TCP',result='success',tcp_flags=['SYN'],node_name='master1'),
                 dict(ts=n//1000,ts_ms=n+5,src='10.0.0.2',src_port=443,dst='10.0.0.1',dst_port=50500,
                   proto='TCP',result='success',tcp_flags=['SYN','ACK'],node_name='master1'),
                 dict(ts=n//1000,ts_ms=n+7,src='10.0.0.1',src_port=50500,dst='10.0.0.2',dst_port=443,
                   proto='TCP',result='success',tcp_flags=['ACK'],node_name='master1')]
            with S.connect() as db:
                for evt in src:
                    values=S.validate_event(evt)
                    db.execute('''INSERT INTO events (ts,src,dst,dst_port,result,bytes_in,bytes_out,duration_ms,
                    src_namespace,dst_namespace,proto,src_port,ts_ms,tcp_flags,drop_reason,node_name,observation_point,verdict)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',values)
            found=S.tcp_search('10.0.0.2',5)
            self.assertEqual(len(found['connections']),1)
            self.assertEqual(found['connections'][0]['event_count'],3)
            self.assertIn('SYN / SYN+ACK / ACK 관측', A.analyze(found['_episodes'][0])['handshake'])
            self.assertEqual(S.tcp_search('10.9.9.9',5)['connections'],[])
    def test_flags_string_and_dict(self):
        self.assertEqual(A.tcp_flags({'FIN':True,'ACK':True}),'ACK,FIN')
        self.assertEqual(A.tcp_flags('RST|ACK'),'ACK,RST')

if __name__=='__main__':unittest.main()
