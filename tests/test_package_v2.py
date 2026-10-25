"""v2 packaging invariants; no external services required."""
import unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
class V2PackageTests(unittest.TestCase):
    def test_labels_and_ports(self):
        dash=(BASE/'k8s/20-dashboard.yaml').read_text()
        gf=(BASE/'k8s/50-grafana.yaml').read_text()
        self.assertIn('nodePort: 31800',dash)
        self.assertIn('nodePort: 31300',gf)
        self.assertIn('local/https-dashboard:v2',dash)
        self.assertIn('local/lifecycle-grafana:v2',gf)
    def test_reset_scope(self):
        reset=(BASE/'scripts/reset.sh').read_text()
        self.assertIn('DELETE OPENCODE V2',reset)
        self.assertIn('kubectl delete namespace opencode',reset)
        self.assertIn('tar -C /opt -czf',reset)
        self.assertNotIn('kubectl delete namespace kube-system',reset)
    def test_ingest_token_normalized(self):
        install=(BASE/'scripts/install.sh').read_text()
        collector=(BASE/'collector/collector.py').read_text()
        dash=(BASE/'dashboard/server.py').read_text()
        self.assertIn('INGEST_TOKEN_NORMALIZED',install)
        self.assertIn('.strip()',collector)
        self.assertIn('.strip()',dash)
if __name__=='__main__':unittest.main()
