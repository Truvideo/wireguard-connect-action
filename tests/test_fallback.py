import datetime
import http.client
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vpn

API = 'https://api.github.com/meta'
FALLBACK = 'https://raw.githubusercontent.com/Truvideo/github-ips/master/github-ipv4.json'
NOW = 1794974700
RANGES = ['140.82.' + str(i) + '.0/24' for i in range(112, 128, 2)] + [
    '185.199.108.0/24', '185.199.110.0/24']
SNAPSHOT = {
    'schema_version': 1,
    'source': API,
    'fetched_at': datetime.datetime.fromtimestamp(NOW, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
    'ipv4': RANGES,
}


class Response(io.BytesIO):
    def __init__(self, error=None):
        super().__init__(json.dumps(SNAPSHOT).encode())
        self.error = error

    def read(self, size=-1):
        if self.error is not None:
            raise self.error
        return super().read(size)


class ProtocolFailureTests(unittest.TestCase):
    def fetch(self, primary_error, during_read=True, fallback_error=None):
        requests = []

        def open_response(request, timeout):
            requests.append(request.full_url)
            if request.full_url == API:
                if not during_read:
                    raise primary_error
                return Response(primary_error)
            self.assertEqual(request.full_url, FALLBACK)
            return Response(fallback_error)

        opener = Mock()
        opener.open.side_effect = open_response
        self.requests = requests
        self.log = io.StringIO()
        with patch.object(vpn.urllib.request, 'build_opener', return_value=opener), \
                patch.object(vpn.time, 'time', return_value=NOW), \
                patch('sys.stderr', self.log):
            return vpn.fetch_github_ranges()

    def test_truncated_primary_response_uses_valid_snapshot(self):
        error = http.client.IncompleteRead(b'synthetic-sensitive-partial-body', 100)
        result = self.fetch(error)
        self.assertEqual(result, vpn.github_ranges({service: RANGES for service in ('web', 'api', 'git')}))
        self.assertEqual(self.requests, [API, FALLBACK])
        self.assertIn('IncompleteRead', self.log.getvalue())
        self.assertNotIn('synthetic-sensitive-partial-body', self.log.getvalue())

    def test_other_http_protocol_errors_use_valid_snapshot(self):
        for error in (http.client.BadStatusLine('synthetic-status'),
                      http.client.RemoteDisconnected(), http.client.HTTPException()):
            with self.subTest(error=type(error).__name__):
                self.assertEqual(len(self.fetch(error, during_read=False)), len(RANGES))
                self.assertEqual(self.requests, [API, FALLBACK])

    def test_truncated_fallback_still_fails_closed(self):
        with self.assertRaises(vpn.ActionError):
            self.fetch(http.client.IncompleteRead(b'primary'),
                       fallback_error=http.client.IncompleteRead(b'fallback'))
        self.assertEqual(self.requests, [API, FALLBACK])

    def test_interruption_does_not_try_the_fallback(self):
        with self.assertRaises(vpn.ActionInterrupted):
            self.fetch(vpn.ActionInterrupted('WireGuard operation interrupted.'))
        self.assertEqual(self.requests, [API])

    def test_interruption_during_fallback_propagates(self):
        with self.assertRaises(vpn.ActionInterrupted):
            self.fetch(http.client.IncompleteRead(b'primary'),
                       fallback_error=vpn.ActionInterrupted('WireGuard operation interrupted.'))
        self.assertEqual(self.requests, [API, FALLBACK])


if __name__ == '__main__':
    unittest.main()
