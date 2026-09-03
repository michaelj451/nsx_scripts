#!/usr/bin/env python3
"""
tests/test_pan_rest_client.py

Offline tests for the Panorama REST client. No network: the requests session
is a fake.

    python -m unittest tests/test_pan_rest_client.py -v
"""

from __future__ import annotations

import json
import logging
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "app") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "app"))

logging.disable(logging.CRITICAL)

from palo.pan_rest_client import PanRestClient, PanRestError  # noqa: E402

BASE_ENV = {
    "panorama": "pano-fake.lab.local",
    "PANORAMA_TLS_VERIFY": "false",
    "PANORAMA_USERNAME": "admin",
    "PANORAMA_PASSWORD": "adminpw",
    "agent_user": "agentuser",
    "agent_password": "agentpw",
}

KEYGEN_XML = "<response status='success'><result><key>FAKEKEY123</key></result></response>"


class FakeResponse:
    def __init__(self, status_code=200, text="", body=None):
        self.status_code = status_code
        self.text = text if body is None else json.dumps(body)
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no JSON")
        return self._body


class FakeSession:
    """Records GETs; answers keygen with a key and REST calls from a routing
    table of resource-substring -> FakeResponse."""

    def __init__(self, routes=None, keygen=None):
        self.routes = routes or {}
        self.keygen = keygen or FakeResponse(text=KEYGEN_XML)
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append({"url": url, "params": dict(params or {}), "headers": dict(headers or {})})
        if "/api/" in url and (params or {}).get("type") == "keygen":
            return self.keygen
        for frag, resp in self.routes.items():
            if frag in url:
                return resp
        return FakeResponse(status_code=404, text="not found")


def make_client(session, **kwargs):
    kwargs.setdefault("user_env", "agent_user")
    kwargs.setdefault("password_env", "agent_password")
    return PanRestClient.from_env(BASE_ENV, load_env=False, session=session, **kwargs)


class TestConstruction(unittest.TestCase):
    def test_agent_credentials_resolved_from_named_vars(self):
        c = make_client(FakeSession())
        self.assertEqual(c.username, "agentuser")
        self.assertEqual(c.password, "agentpw")
        self.assertEqual(c.env.hostname, "pano-fake.lab.local")
        self.assertFalse(c.env.verify)

    def test_missing_agent_vars_raise(self):
        env = dict(BASE_ENV)
        del env["agent_password"]
        with self.assertRaises(PanRestError):
            PanRestClient.from_env(env, load_env=False, user_env="agent_user",
                                   password_env="agent_password")

    def test_user_env_without_password_env_raises(self):
        with self.assertRaises(PanRestError):
            PanRestClient.from_env(BASE_ENV, load_env=False, user_env="agent_user")

    def test_default_resolution_uses_admin_credentials(self):
        c = PanRestClient.from_env(BASE_ENV, load_env=False, session=FakeSession())
        self.assertEqual(c.username, "admin")

    def test_stored_api_key_ignored_for_named_account(self):
        env = dict(BASE_ENV, PANORAMA_API_KEY="ADMINKEY")
        c = PanRestClient.from_env(env, load_env=False, session=FakeSession(),
                                   user_env="agent_user", password_env="agent_password")
        self.assertIsNone(c._api_key)  # must keygen as agentuser, not reuse the admin key

    def test_host_override(self):
        c = make_client(FakeSession(), host="pano2.lab.local")
        self.assertEqual(c.env.hostname, "pano2.lab.local")

    def test_rest_version_normalised(self):
        c = make_client(FakeSession(), rest_version="10.2")
        self.assertEqual(c.rest_version, "v10.2")
        c = PanRestClient.from_env(dict(BASE_ENV, PANORAMA_REST_VERSION="v11.1"),
                                   load_env=False, user_env="agent_user",
                                   password_env="agent_password")
        self.assertEqual(c.rest_version, "v11.1")


class TestAuth(unittest.TestCase):
    def test_keygen_once_then_header(self):
        s = FakeSession(routes={"/restapi/": FakeResponse(body={
            "@status": "success", "result": {"@total-count": "0", "entry": []}})})
        c = make_client(s)
        c.list_addresses()
        c.list_addresses()
        keygens = [x for x in s.calls if x["params"].get("type") == "keygen"]
        rest = [x for x in s.calls if "/restapi/" in x["url"]]
        self.assertEqual(len(keygens), 1)
        self.assertTrue(all(x["headers"].get("X-PAN-KEY") == "FAKEKEY123" for x in rest))

    def test_keygen_failure_raises(self):
        s = FakeSession(keygen=FakeResponse(
            text="<response status='error' code='403'><result><msg>Invalid credential</msg></result></response>"))
        with self.assertRaises(PanRestError):
            make_client(s).api_key


class TestGet(unittest.TestCase):
    def _client(self, resp):
        return make_client(FakeSession(routes={"/restapi/": resp}))

    def test_entries_from_list(self):
        c = self._client(FakeResponse(body={"@status": "success", "result": {
            "@total-count": "2", "entry": [{"@name": "a"}, {"@name": "b"}]}}))
        self.assertEqual([e["@name"] for e in c.list_address_groups()], ["a", "b"])

    def test_entries_single_dict_wrapped(self):
        c = self._client(FakeResponse(body={"@status": "success", "result": {
            "@total-count": "1", "entry": {"@name": "solo"}}}))
        self.assertEqual(c.list_addresses(), [{"@name": "solo"}])

    def test_entries_empty_result(self):
        c = self._client(FakeResponse(body={"@status": "success", "result": {"@total-count": "0"}}))
        self.assertEqual(c.list_tags(), [])

    def test_device_group_param_shape(self):
        s = FakeSession(routes={"/restapi/": FakeResponse(body={
            "@status": "success", "result": {"entry": []}})})
        c = make_client(s)
        c.list_security_pre_rules("dg-4")
        call = [x for x in s.calls if "/restapi/" in x["url"]][0]
        self.assertIn("Policies/SecurityPreRules", call["url"])
        self.assertEqual(call["params"]["location"], "device-group")
        self.assertEqual(call["params"]["device-group"], "dg-4")

    def test_device_group_location_without_name_raises(self):
        c = self._client(FakeResponse(body={"@status": "success", "result": {}}))
        with self.assertRaises(PanRestError):
            c.get("Objects/Addresses", location="device-group")

    def test_http_403_raises_with_hint(self):
        c = self._client(FakeResponse(status_code=403, body={
            "code": 7, "message": "Unauthorized"}))
        with self.assertRaises(PanRestError) as ctx:
            c.list_addresses()
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("probe_api_permissions", str(ctx.exception))

    def test_rest_level_error_status_raises(self):
        c = self._client(FakeResponse(body={"@status": "error", "@code": "5",
                                            "message": "bad location"}))
        with self.assertRaises(PanRestError):
            c.list_addresses()

    def test_non_json_raises(self):
        c = self._client(FakeResponse(status_code=200, text="<html>login</html>"))
        with self.assertRaises(PanRestError):
            c.list_addresses()

    def test_list_device_groups_sorted_names(self):
        c = self._client(FakeResponse(body={"@status": "success", "result": {
            "entry": [{"@name": "dg-5"}, {"@name": "dg-3"}]}}))
        self.assertEqual(c.list_device_groups(), ["dg-3", "dg-5"])


if __name__ == "__main__":
    unittest.main()
