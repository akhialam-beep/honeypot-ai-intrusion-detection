import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import MagicMock, patch
from database import push_dashboard as sender

class SenderTests(unittest.TestCase):
    def test_database_snapshot_reversed_and_authenticated(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)/'.config/honeypot-ai'
            folder.mkdir(parents=True)
            (folder/'dashboard-upload.json').write_text(json.dumps({'url':'https://example.org/api/events','token':'x'*40}))
            (folder/'db-password').write_text('test-only')
            conn = MagicMock()
            conn.cursor.return_value.fetchall.return_value = [{'eventid':'new'}, {'eventid':'old'}]
            connector = types.SimpleNamespace(connect=MagicMock(return_value=conn))
            opener = MagicMock()
            opener.open.return_value.__enter__.return_value = io.BytesIO(b'{"accepted":2,"received_at":"test"}')
            with patch.object(sender.Path,'home',return_value=Path(directory)), patch.dict('sys.modules',mariadb=connector), patch.object(sender,'build_opener',return_value=opener):
                sender.main()
            req = opener.open.call_args.args[0]
            self.assertEqual(json.loads(req.data)['events'], [{'eventid':'old'},{'eventid':'new'}])
            self.assertEqual(req.get_header('Authorization'),'Bearer '+'x'*40)
            conn.close.assert_called_once()

    def test_redirects_are_not_followed(self):
        self.assertIsNone(sender.NoRedirect().redirect_request(None,None,302,'',{},'https://other.org'))
