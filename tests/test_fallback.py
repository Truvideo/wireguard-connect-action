import datetime
import http.client
import io
import json
import signal
import time
import urllib.error
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
    def __init__(self, error=None, payload=None):
        value = SNAPSHOT if payload is None else payload
        super().__init__(value if isinstance(value, bytes) else json.dumps(value).encode())
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
                patch.object(vpn.time, 'sleep'), \
                patch('sys.stderr', self.log):
            return vpn.fetch_github_ranges()

    def test_truncated_primary_response_uses_valid_snapshot(self):
        error = http.client.IncompleteRead(b'synthetic-sensitive-partial-body', 100)
        result = self.fetch(error)
        self.assertEqual(result, vpn.github_ranges({service: RANGES for service in ('web', 'api', 'git')}))
        self.assertEqual(self.requests, [API, API, FALLBACK])
        self.assertIn('IncompleteRead', self.log.getvalue())
        self.assertNotIn('synthetic-sensitive-partial-body', self.log.getvalue())

    def test_other_http_protocol_errors_use_valid_snapshot(self):
        for error in (http.client.BadStatusLine('synthetic-status'),
                      http.client.RemoteDisconnected(), http.client.HTTPException()):
            with self.subTest(error=type(error).__name__):
                self.assertEqual(len(self.fetch(error, during_read=False)), len(RANGES))
                self.assertEqual(self.requests, [API, API, FALLBACK])

    def test_truncated_fallback_still_fails_closed(self):
        with self.assertRaises(vpn.ActionError):
            self.fetch(http.client.IncompleteRead(b'primary'),
                       fallback_error=http.client.IncompleteRead(b'fallback'))
        self.assertEqual(self.requests, [API, API, FALLBACK, FALLBACK])

    def test_interruption_does_not_try_the_fallback(self):
        with self.assertRaises(vpn.ActionInterrupted):
            self.fetch(vpn.ActionInterrupted('WireGuard operation interrupted.'))
        self.assertEqual(self.requests, [API])

    def test_interruption_during_fallback_propagates(self):
        with self.assertRaises(vpn.ActionInterrupted):
            self.fetch(http.client.IncompleteRead(b'primary'),
                       fallback_error=vpn.ActionInterrupted('WireGuard operation interrupted.'))
        self.assertEqual(self.requests, [API, API, FALLBACK])


class RetryTests(unittest.TestCase):
    def execute(self, outcomes, sleep_error=None):
        self.opener = Mock()
        self.opener.open.side_effect = [Response(payload=value) if isinstance(value, (dict, bytes)) else value for value in outcomes]
        self.log = io.StringIO()
        with patch.object(vpn.urllib.request, 'build_opener', return_value=self.opener), \
                patch.object(vpn.time, 'time', return_value=NOW), \
                patch.object(vpn.time, 'sleep', side_effect=sleep_error) as sleep, \
                patch('sys.stderr', self.log):
            self.sleep = sleep
            return vpn.fetch_github_ranges()

    def urls(self):
        return [call.args[0].full_url for call in self.opener.open.call_args_list]

    def http_error(self, code, headers=None):
        return urllib.error.HTTPError(API, code, 'Synthetic failure', headers or {}, None)

    def test_transient_api_error_retries_once_then_succeeds(self):
        meta = {service: RANGES for service in ('web', 'api', 'git')}
        self.assertEqual(len(self.execute([self.http_error(503), meta])), len(RANGES))
        self.assertEqual(self.urls(), [API, API])
        self.sleep.assert_called_once_with(2)
        self.assertTrue(all(call.kwargs['timeout'] <= 10 for call in self.opener.open.call_args_list))

    def test_timeout_connection_reset_and_truncated_read_are_retried(self):
        meta = {service: RANGES for service in ('web', 'api', 'git')}
        for failure in (TimeoutError(), urllib.error.URLError(TimeoutError()),
                        ConnectionResetError(), Response(http.client.IncompleteRead(b'partial'))):
            with self.subTest(error=type(failure).__name__):
                self.assertEqual(len(self.execute([failure, meta])), len(RANGES))
                self.assertEqual(self.urls(), [API, API])
                self.sleep.assert_called_once_with(2)

    def test_rate_limits_skip_directly_to_fallback(self):
        for code in (403, 429):
            with self.subTest(code=code):
                self.assertEqual(len(self.execute([self.http_error(code), SNAPSHOT])), len(RANGES))
                self.assertEqual(self.urls(), [API, FALLBACK])
                self.sleep.assert_not_called()

    def test_retry_after_is_not_ignored(self):
        self.execute([self.http_error(503, {'Retry-After': '30'}), SNAPSHOT])
        self.assertEqual(self.urls(), [API, FALLBACK])
        self.sleep.assert_not_called()

    def test_exhausted_rate_limit_is_not_retried(self):
        self.execute([self.http_error(503, {'X-RateLimit-Remaining': '0'}), SNAPSHOT])
        self.assertEqual(self.urls(), [API, FALLBACK])
        self.sleep.assert_not_called()

    def test_fallback_can_retry_once_after_a_transient_failure(self):
        self.execute([self.http_error(403), self.http_error(502), SNAPSHOT])
        self.assertEqual(self.urls(), [API, FALLBACK, FALLBACK])
        self.sleep.assert_called_once_with(2)

    def test_attempts_are_bounded_for_each_source(self):
        with self.assertRaises(vpn.ActionError):
            self.execute([self.http_error(503), self.http_error(503), TimeoutError(), TimeoutError()])
        self.assertEqual(self.urls(), [API, API, FALLBACK, FALLBACK])
        self.assertEqual(self.sleep.call_count, 2)

    def test_invalid_json_is_not_retried(self):
        self.execute([b'not json', SNAPSHOT])
        self.assertEqual(self.urls(), [API, FALLBACK])
        self.sleep.assert_not_called()

    def test_expired_snapshot_is_not_retried(self):
        with self.assertRaises(vpn.ActionError):
            self.execute([self.http_error(403), dict(SNAPSHOT, fetched_at='2020-01-01T00:00:00Z')])
        self.assertEqual(self.urls(), [API, FALLBACK])
        self.sleep.assert_not_called()

    def test_other_http_errors_are_not_retried(self):
        self.execute([self.http_error(404), SNAPSHOT])
        self.assertEqual(self.urls(), [API, FALLBACK])
        self.sleep.assert_not_called()

    def test_interruption_during_retry_delay_propagates(self):
        handler = signal.getsignal(signal.SIGALRM)
        with self.assertRaises(vpn.ActionInterrupted):
            self.execute([TimeoutError(), SNAPSHOT], vpn.ActionInterrupted('WireGuard operation interrupted.'))
        self.assertEqual(self.urls(), [API])
        self.assertEqual(signal.getsignal(signal.SIGALRM), handler)

    def test_exhausted_total_budget_prevents_another_request(self):
        clock = [0.0]
        opener = Mock()
        def timeout(request, timeout):
            clock[0] = 45.0
            raise TimeoutError()
        opener.open.side_effect = timeout
        with patch.object(vpn.urllib.request, 'build_opener', return_value=opener), \
                patch.object(vpn.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(vpn.time, 'sleep') as sleep, patch('sys.stderr', io.StringIO()):
            with self.assertRaises(vpn.DownloadBudgetExpired):
                vpn.fetch_github_ranges()
        self.assertEqual(opener.open.call_count, 1)
        sleep.assert_not_called()

    def test_hard_budget_interrupts_a_blocked_response_read(self):
        class SlowResponse(Response):
            def read(self, size=-1):
                time.sleep(0.5)
                return super().read(size)
        opener = Mock()
        opener.open.return_value = SlowResponse()
        handler = signal.getsignal(signal.SIGALRM)
        with patch.object(vpn.urllib.request, 'build_opener', return_value=opener), \
                patch.object(vpn, 'DOWNLOAD_BUDGET_SECONDS', 0.05), patch('sys.stderr', io.StringIO()):
            with self.assertRaises(vpn.DownloadBudgetExpired):
                vpn.fetch_github_ranges()
        self.assertEqual(opener.open.call_count, 1)
        self.assertEqual(signal.getsignal(signal.SIGALRM), handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL)[0], 0)


if __name__ == '__main__':
    unittest.main()
