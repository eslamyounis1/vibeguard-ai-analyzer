import json
from vibeguard.models.finding import ScanResult


class JsonReporter:
    def report(self, result: ScanResult) -> str:
        return json.dumps(result.to_dict(), indent=2)
