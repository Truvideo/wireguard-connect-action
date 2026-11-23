import contextlib
import http.client
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.error
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vpn

API = 'https://api.github.com/meta'
TOKEN = 'synthetic-private-job-token'
METADATA = {service: ['140.82.112.0/20'] for service in ('web', 'api', 'git')}


class Response(io.BytesIO):
    status = 200
    headers = {'X-RateLimit-Limit': '1000', 'X-RateLimit-Remaining': '999'}

    def __init__(self, payload=METADATA):
        super().__init__(payload if isinstance(payload, bytes) else json.dumps(payload).encode())


class MetadataTests(unittest.TestCase):
    def fetch(self, response):
        self.opener = Mock()
        self.opener.open.side_effect = [response]
        self.log = io.StringIO()
        with patch.object(vpn.urllib.request, 'build_opener', return_value=self.opener) as build, \
                contextlib.redirect_stderr(self.log):
            self.build = build
            return vpn.fetch_github_metadata(TOKEN)

    def assert_single_api_request(self):
        self.opener.open.assert_called_once()
        request = self.opener.open.call_args.args[0]
        self.assertEqual(request.full_url, API)
        self.assertEqual(request.get_header('Authorization'), 'Bearer ' + TOKEN)
        self.assertEqual(self.opener.open.call_args.kwargs['timeout'], 20)

    def test_authenticated_metadata_request_and_safe_diagnostics(self):
        self.assertEqual(self.fetch(Response()), METADATA)
        self.assert_single_api_request()
        self.assertIn('HTTP status: 200', self.log.getvalue())
        self.assertIn('X-RateLimit-Remaining: 999', self.log.getvalue())
        self.assertNotIn(TOKEN, self.log.getvalue())
        self.assertNotIn('140.82.112.0', self.log.getvalue())

    def test_http_errors_propagate_without_fallback_or_sensitive_logs(self):
        for status in (401, 403, 429, 503):
            with self.subTest(status=status):
                error = urllib.error.HTTPError(API, status, TOKEN,
                    {'X-RateLimit-Remaining': '0'}, io.BytesIO(b'sensitive-response-body'))
                with self.assertRaises(urllib.error.HTTPError):
                    self.fetch(error)
                self.assert_single_api_request()
                self.assertIn('HTTP status: ' + str(status), self.log.getvalue())
                self.assertNotIn(TOKEN, self.log.getvalue())
                self.assertNotIn('sensitive-response-body', self.log.getvalue())

    def test_network_and_protocol_failures_do_not_fetch_another_source(self):
        for error in (TimeoutError(), urllib.error.URLError('synthetic failure'),
                      http.client.IncompleteRead(b'sensitive-partial-response')):
            with self.subTest(error=type(error).__name__):
                with self.assertRaises(type(error)):
                    self.fetch(error)
                self.assert_single_api_request()
                self.assertNotIn('sensitive-partial-response', self.log.getvalue())

    def test_invalid_json_does_not_fetch_another_source(self):
        with self.assertRaises(ValueError):
            self.fetch(Response(b'not-json'))
        self.assert_single_api_request()

    def test_redirects_cannot_forward_the_token(self):
        self.fetch(Response())
        proxy_handler, redirect_handler = self.build.call_args.args
        self.assertEqual(proxy_handler.proxies, {})
        request = self.opener.open.call_args.args[0]
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status), self.assertRaises(vpn.ActionError):
                redirect_handler.redirect_request(request, None, status, '', {},
                                                  'https://other.example/meta')

    def test_multicast_ranges_are_rejected(self):
        with self.assertRaises(vpn.ActionError):
            vpn.github_ranges({service: ['224.0.0.0/24'] for service in ('web', 'api', 'git')})

    def test_token_removed_before_subprocess_execution(self):
        class StopBeforeBrew(Exception):
            pass

        def command(*args, **kwargs):
            self.assertEqual(args[:2], ('brew', 'install'))
            self.assertNotIn('INPUT_GITHUB-TOKEN', os.environ)
            self.assertNotIn('INPUT_CONFIG', os.environ)
            raise StopBeforeBrew()

        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, {'INPUT_GITHUB-TOKEN': TOKEN, 'INPUT_CONFIG': 'synthetic-config'}), \
                patch.object(vpn.platform, 'system', return_value='Darwin'), \
                patch.object(vpn, 'interface_name_file', return_value=Mock(exists=lambda: False)), \
                patch.object(vpn, 'state_path', return_value=Path(directory)), \
                patch.object(vpn, 'parse_config'), \
                patch.object(vpn, 'run', side_effect=command), \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(StopBeforeBrew):
                vpn.connect(directory)

    def test_missing_token_fails_before_subprocess_execution(self):
        with patch.dict(os.environ, {'INPUT_GITHUB-TOKEN': '', 'INPUT_CONFIG': ''}), \
                patch.object(vpn, 'run') as command:
            with self.assertRaises(vpn.ActionError):
                vpn.connect('/unused')
        command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
