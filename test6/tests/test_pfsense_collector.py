from types import SimpleNamespace

from src.pfsense_collector import PfSenseLogCollector


class FakeSFTP:
    def __init__(self, files):
        self.files = files

    def stat(self, path):
        if path not in self.files:
            raise FileNotFoundError(2, "No such file", path)
        return SimpleNamespace(st_mtime=self.files[path])

    def listdir(self, path):
        prefix = path.rstrip("/") + "/"
        return sorted(
            {
                remainder.split("/", 1)[0]
                for file_path in self.files
                if file_path.startswith(prefix)
                for remainder in [file_path[len(prefix):]]
                if "/" in remainder
            }
        )


def test_resolves_eve_json_from_actual_interface_directory():
    collector = PfSenseLogCollector(
        {"suricata_log_path": "/var/log/suricata/suricata_wrong/eve.json"}
    )
    sftp = FakeSFTP(
        {
            "/var/log/suricata/suricata_em0/eve.json": 10,
            "/var/log/suricata/suricata_em1/eve.json": 20,
        }
    )

    assert (
        collector._resolve_remote_log_path(sftp)
        == "/var/log/suricata/suricata_em1/eve.json"
    )


def test_keeps_configured_path_when_it_exists():
    path = "/var/log/suricata/suricata_em0/eve.json"
    collector = PfSenseLogCollector({"suricata_log_path": path})

    assert collector._resolve_remote_log_path(FakeSFTP({path: 10})) == path
