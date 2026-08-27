#!/usr/bin/env python3
"""
tests/test_panos_client.py

Offline tests for the Panorama env resolver, the pan-os-python wrapper, and
the auth script's pure helpers. No network: the Panorama device is a fake.

    python -m unittest tests/test_panos_client.py -v
"""

from __future__ import annotations

import importlib.util
import logging
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "app") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "app"))

logging.disable(logging.CRITICAL)

from palo import pan_env  # noqa: E402
from palo.panos_client import PanosClient, PanosClientError  # noqa: E402


def _load_auth_script():
    spec = importlib.util.spec_from_file_location(
        "panorama_auth", REPO_ROOT / "tools" / "pan" / "panorama_auth.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeDevice:
    """Stands in for panos.panorama.Panorama."""

    def __init__(self, *, api_key="FAKEKEY1234567890", fail_with=None):
        self._api_key = api_key
        self.fail_with = fail_with
        self.calls = []

    @property
    def api_key(self):
        if isinstance(self.fail_with, Exception) and self._api_key is None:
            raise self.fail_with
        return self._api_key

    def refresh_system_info(self):
        self.calls.append("refresh_system_info")
        if self.fail_with:
            raise self.fail_with

    def show_system_info(self):
        self.calls.append("show_system_info")
        return {"system": {"hostname": "pano-fake", "serial": "0001", "sw-version": "11.1.4", "model": "Panorama"}}

    def op(self, cmd, xml=True):
        self.calls.append(("op", cmd))
        return cmd


class PanEnvTests(unittest.TestCase):
    def test_lab_naming_convention(self):
        env = pan_env.resolve_panorama_env({"ppanorama": "pano4.lab.local", "vm_username": "u", "vm_password": "p"})
        self.assertEqual(env.url, "https://pano4.lab.local")
        self.assertEqual((env.hostname, env.port, env.scheme), ("pano4.lab.local", 443, "https"))
        self.assertTrue(env.verify)
        self.assertFalse(env.has_api_key)
        self.assertTrue(env.has_password_auth)
        self.assertEqual(env.sources["host"], "ppanorama")
        self.assertEqual(env.sources["username"], "vm_username")

    def test_canonical_names_and_key_preferred(self):
        env = pan_env.resolve_panorama_env({
            "PANORAMA_URL": "https://pano.example.com:8443/",
            "PANORAMA_API_KEY": "K",
            "PANORAMA_USERNAME": "u", "PANORAMA_PASSWORD": "p",
            "PANORAMA_TLS_VERIFY": "false",
        })
        self.assertEqual(env.url, "https://pano.example.com:8443")
        self.assertEqual(env.port, 8443)
        self.assertFalse(env.verify)
        self.assertTrue(env.has_api_key)
        self.assertEqual(env.describe()["auth"], "api_key")

    def test_precedence_matches_legacy_client(self):
        env = pan_env.resolve_panorama_env({
            "panorama": "first.lab.local", "ppanorama": "second.lab.local", "PANORAMA_URL": "third",
            "PANORAMA_API_KEY": "K",
        })
        self.assertEqual(env.hostname, "first.lab.local")

    def test_port_var_and_host_port(self):
        env = pan_env.resolve_panorama_env({"PANORAMA_HOST": "h", "PANORAMA_PORT": "8443", "PANORAMA_API_KEY": "K"})
        self.assertEqual(env.port, 8443)
        env = pan_env.resolve_panorama_env({"PANORAMA_HOST": "h:9443", "PANORAMA_PORT": "8443", "PANORAMA_API_KEY": "K"})
        self.assertEqual(env.port, 9443)

    def test_missing_host_raises(self):
        with self.assertRaises(pan_env.PanoramaEnvError):
            pan_env.resolve_panorama_env({"PANORAMA_API_KEY": "K"})

    def test_missing_credentials_raises_unless_optional(self):
        with self.assertRaises(pan_env.PanoramaEnvError):
            pan_env.resolve_panorama_env({"ppanorama": "h"})
        env = pan_env.resolve_panorama_env({"ppanorama": "h"}, require_auth=False)
        self.assertEqual(env.describe()["auth"], "none")

    def test_describe_never_contains_secrets(self):
        env = pan_env.resolve_panorama_env({"ppanorama": "h", "PANORAMA_API_KEY": "SECRETKEY", "vm_password": "SECRETPW"})
        text = str(env.describe())
        self.assertNotIn("SECRETKEY", text)
        self.assertNotIn("SECRETPW", text)


class PanosClientTests(unittest.TestCase):
    ENV = {"ppanorama": "pano4.lab.local", "vm_username": "u", "vm_password": "p"}

    def test_connect_returns_system_dict_and_caches(self):
        dev = FakeDevice()
        client = PanosClient.from_env(self.ENV, load_env=False, device=dev)
        system = client.connect()
        self.assertEqual(system["hostname"], "pano-fake")
        self.assertEqual(client.system_info()["serial"], "0001")
        self.assertEqual(dev.calls, ["refresh_system_info", "show_system_info"])

    def test_api_key_and_fingerprint(self):
        client = PanosClient.from_env(self.ENV, load_env=False, device=FakeDevice(api_key="ABCDEFGH"))
        self.assertEqual(client.api_key, "ABCDEFGH")
        self.assertEqual(len(client.api_key_fingerprint()), 12)

    def test_failures_become_panos_client_error_with_hint(self):
        dev = FakeDevice(fail_with=RuntimeError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"))
        client = PanosClient.from_env(self.ENV, load_env=False, device=dev)
        with self.assertRaises(PanosClientError) as cm:
            client.connect()
        self.assertIn("PANORAMA_TLS_VERIFY=false", str(cm.exception))

    def test_verify_api_key_false_on_bad_credentials_but_raises_otherwise(self):
        bad = PanosClient.from_env(self.ENV, load_env=False, device=FakeDevice(fail_with=RuntimeError("Invalid credentials.")))
        self.assertFalse(bad.verify_api_key())
        down = PanosClient.from_env(self.ENV, load_env=False, device=FakeDevice(fail_with=RuntimeError("Connection refused")))
        with self.assertRaises(PanosClientError):
            down.verify_api_key()

    def test_env_error_surfaces_as_client_error(self):
        with self.assertRaises(PanosClientError):
            PanosClient.from_env({"vm_username": "u"}, load_env=False)

    def test_real_device_uses_key_only_when_present(self):
        """No network: constructing the pan-os-python object is lazy and offline."""
        try:
            import panos  # noqa: F401
        except ImportError:
            self.skipTest("pan-os-python not installed")
        client = PanosClient.from_env({"ppanorama": "h", "PANORAMA_API_KEY": "K", "vm_username": "u", "vm_password": "p"},
                                      load_env=False)
        dev = client.device
        self.assertEqual(dev._api_key, "K")
        self.assertIsNone(dev._api_username)
        client2 = PanosClient.from_env({"ppanorama": "h", "vm_username": "u", "vm_password": "p", "PANORAMA_TLS_VERIFY": "false"},
                                       load_env=False)
        dev2 = client2.device
        self.assertIsNone(dev2._api_key)
        self.assertEqual(dev2._api_username, "u")
        self.assertIsNotNone(dev2._ssl_context)
        self.assertIn("ssl_context", dev2._xapi_kwargs())


class AuthScriptHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.auth = _load_auth_script()

    def test_mask_key(self):
        self.assertEqual(self.auth.mask_key(None), "(none)")
        self.assertEqual(self.auth.mask_key("short"), "***** (len=5)")
        masked = self.auth.mask_key("ABCD0123456789WXYZ")
        self.assertTrue(masked.startswith("ABCD...WXYZ"))
        self.assertNotIn("0123456789", masked)

    def test_upsert_env_var_add_then_refuse_then_force(self):
        env = Path(tempfile.mkdtemp()) / ".env"
        env.write_text("NSX_LM1=a\nvm_username=u\n", encoding="utf-8")
        self.assertEqual(self.auth.upsert_env_var(env, "PANORAMA_API_KEY", "K1"), "added")
        text = env.read_text()
        self.assertIn("NSX_LM1=a\n", text)
        self.assertIn("PANORAMA_API_KEY=K1\n", text)
        with self.assertRaises(FileExistsError):
            self.auth.upsert_env_var(env, "PANORAMA_API_KEY", "K2")
        self.assertEqual(self.auth.upsert_env_var(env, "PANORAMA_API_KEY", "K2", force=True), "replaced")
        text = env.read_text()
        self.assertIn("PANORAMA_API_KEY=K2\n", text)
        self.assertNotIn("K1", text)
        self.assertEqual(text.count("PANORAMA_API_KEY="), 1)

    def test_upsert_env_var_creates_missing_file(self):
        env = Path(tempfile.mkdtemp()) / ".env"
        self.assertEqual(self.auth.upsert_env_var(env, "PANORAMA_API_KEY", "K"), "added")
        self.assertIn("PANORAMA_API_KEY=K", env.read_text())


if __name__ == "__main__":
    unittest.main()
