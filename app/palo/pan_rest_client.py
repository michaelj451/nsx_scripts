#!/usr/bin/env python3
"""app/palo/pan_rest_client.py

Panorama REST API client (/restapi/<version>/...). READ-ONLY by design:
this module only issues GETs. It exists for restricted accounts (e.g. the
read-only agent account) whose role denies the XML API's op/config types
but grants REST read access to objects, policies, and network.

Three Panorama clients now exist on purpose:

  app/palo/panorama_api_client.py   raw XML API over requests; xpath-level
                                    get/set/edit/delete and commit. Needs an
                                    account with XML config rights.
  app/palo/panos_client.py          pan-os-python object model. Needs XML
                                    op/config rights.
  app/palo/pan_rest_client.py       THIS FILE. REST GETs only. Works with a
                                    role that grants only read-only REST
                                    access (plus keygen).

All three read the target from app/palo/pan_env.py, so the same .env works
for any of them.

Design properties (mirrors PanosClient):
  - from_env() is the only constructor tools should use. `user_env` /
    `password_env` name the .env variables holding the credentials, so a
    tool can run as the restricted account (agent_user/agent_password)
    without disturbing the admin variables.
  - Auth is keygen -> X-PAN-KEY header. A key from PANORAMA_API_KEY is used
    only when no explicit user_env is given (a stored admin key does not
    belong to the restricted account).
  - TLS verification follows PANORAMA_TLS_VERIFY (default true).
  - Credentials are never logged; api_key_fingerprint() is the safe handle.
  - Errors surface as PanRestError carrying the HTTP status and the REST
    error payload's code/message when present.

API surface:
    PanRestClient.from_env(environ=None, *, user_env=None, password_env=None,
                           host=None, rest_version=None, load_env=True)
    .get(resource, *, location=None, device_group=None, name=None, params=None)
          -> dict  the parsed "result" object ({"@total-count": ..., "entry": [...]})
    .entries(resource, ...) -> list[dict]   just the entry list
    .list_addresses(location="shared", device_group=None)
    .list_address_groups(location="shared", device_group=None)
    .list_services(location="shared", device_group=None)
    .list_service_groups(location="shared", device_group=None)
    .list_tags(location="shared", device_group=None)
    .list_security_pre_rules(device_group)
    .list_security_post_rules(device_group)
    .list_nat_pre_rules(device_group)
    .list_device_groups() -> list[str]
    .api_key_fingerprint() -> str

Location handling (Panorama):
    location="shared"                        shared objects
    location="device-group" + device_group   a DG's own objects
Rule endpoints are always device-group scoped; the helpers fill that in.
"""
from __future__ import annotations

import hashlib
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

import requests
import urllib3

from palo.pan_env import PanoramaEnv, PanoramaEnvError, load_repo_env, resolve_panorama_env

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_REST_VERSION = "v11.2"
REST_VERSION_VAR = "PANORAMA_REST_VERSION"


class PanRestError(RuntimeError):
    """Raised for any failure talking to the Panorama REST API."""

    def __init__(self, message: str, *, status_code: int = 0, code: Optional[str] = None):
        self.status_code = status_code
        self.code = code
        super().__init__(message)


@dataclass
class PanRestClient:
    env: PanoramaEnv
    username: str
    password: str
    rest_version: str = DEFAULT_REST_VERSION
    timeout: int = DEFAULT_TIMEOUT_SECONDS
    _api_key: Optional[str] = field(default=None, repr=False)
    _session: Any = field(default=None, repr=False)

    # -----------------------------------------------------------------------
    # Construction
    # -----------------------------------------------------------------------

    @classmethod
    def from_env(
        cls,
        environ: Optional[Mapping[str, str]] = None,
        *,
        user_env: Optional[str] = None,
        password_env: Optional[str] = None,
        host: Optional[str] = None,
        rest_version: Optional[str] = None,
        load_env: bool = True,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        session: Any = None,
    ) -> "PanRestClient":
        """Build a client from .env.

        `user_env`/`password_env` name the environment variables holding the
        credentials (e.g. "agent_user"/"agent_password"). When omitted, the
        canonical PANORAMA_* username/password resolution applies, and a
        stored PANORAMA_API_KEY is used directly if present.

        `host` overrides the .env hostname (same semantics as the perf and
        probe tools). `session` lets tests inject a fake; production callers
        leave it unset.
        """
        if load_env and environ is None:
            load_repo_env()
        import os
        env_map: Mapping[str, str] = environ if environ is not None else os.environ
        try:
            env = resolve_panorama_env(env_map, require_auth=user_env is None)
        except PanoramaEnvError as exc:
            raise PanRestError(str(exc)) from exc

        if user_env is not None or password_env is not None:
            if not (user_env and password_env):
                raise PanRestError("user_env and password_env must be given together.")
            username = (env_map.get(user_env) or "").strip()
            password = (env_map.get(password_env) or "").strip()
            if not username or not password:
                raise PanRestError(
                    f"Credentials not found in .env: {user_env} and/or {password_env} is empty.")
            api_key = None  # a stored admin key does not belong to this account
        else:
            username = env.username or ""
            password = env.password or ""
            api_key = env.api_key
            if not api_key and not (username and password):
                raise PanRestError("No usable Panorama credentials in .env.")

        if host:
            hostname, port, scheme = host.strip(), env.port, env.scheme
            env = PanoramaEnv(hostname=hostname, port=port, scheme=scheme,
                              verify=env.verify, api_key=None, username=username,
                              password=password, sources=dict(env.sources, host="--host"))

        version = (rest_version or env_map.get(REST_VERSION_VAR) or DEFAULT_REST_VERSION).strip()
        if not version.startswith("v"):
            version = f"v{version}"

        return cls(env=env, username=username, password=password,
                   rest_version=version, timeout=timeout,
                   _api_key=api_key, _session=session)

    # -----------------------------------------------------------------------
    # Transport / auth
    # -----------------------------------------------------------------------

    @property
    def session(self):
        if self._session is None:
            s = requests.Session()
            s.verify = self.env.verify
            if not self.env.verify:
                log.warning("TLS certificate verification DISABLED for %s (PANORAMA_TLS_VERIFY=false)",
                            self.env.hostname)
            self._session = s
        return self._session

    @property
    def api_key(self) -> str:
        """Keygen on first use (unless a stored key applied at construction)."""
        if self._api_key is None:
            r = self.session.get(
                f"{self.env.url}/api/",
                params={"type": "keygen", "user": self.username, "password": self.password},
                timeout=self.timeout,
            )
            if r.status_code >= 400:
                raise PanRestError(f"keygen failed for {self.env.url}: HTTP {r.status_code}",
                                   status_code=r.status_code)
            try:
                root = ET.fromstring(r.text)
            except ET.ParseError as exc:
                raise PanRestError(f"keygen returned non-XML from {self.env.url}") from exc
            key = root.findtext("./result/key")
            if root.get("status") != "success" or not key:
                msg = root.findtext(".//line") or root.findtext("./msg") or "no key in response"
                raise PanRestError(f"keygen failed for {self.env.url}: {msg}",
                                   status_code=r.status_code, code=root.get("code"))
            self._api_key = key
        return self._api_key

    def api_key_fingerprint(self) -> str:
        """Short sha256 prefix of the key. Safe to put in logs and reports."""
        return hashlib.sha256(self.api_key.encode("utf-8")).hexdigest()[:12]

    # -----------------------------------------------------------------------
    # Core GET
    # -----------------------------------------------------------------------

    def get(
        self,
        resource: str,
        *,
        location: Optional[str] = None,
        device_group: Optional[str] = None,
        name: Optional[str] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """GET /restapi/<version>/<resource> and return the parsed "result".

        `resource` is the REST path after the version, e.g. "Objects/Addresses"
        or "Policies/SecurityPreRules". `location`/`device_group`/`name` become
        the standard query parameters; `params` merges any extras.
        """
        query: Dict[str, str] = dict(params or {})
        if location is not None:
            query["location"] = location
        if device_group is not None:
            query.setdefault("location", "device-group")
            query["device-group"] = device_group
        if name is not None:
            query["name"] = name
        if query.get("location") == "device-group" and "device-group" not in query:
            raise PanRestError(f"location='device-group' requires a device_group name ({resource}).")

        url = f"{self.env.url}/restapi/{self.rest_version}/{resource.strip('/')}"
        r = self.session.get(url, params=query, headers={"X-PAN-KEY": self.api_key},
                             timeout=self.timeout)
        if r.status_code >= 400:
            code, msg = self._error_detail(r)
            hint = ""
            if r.status_code == 403:
                hint = (" (account lacks REST read access to this resource;"
                        " see tools/pan/probe_api_permissions.py)")
            raise PanRestError(f"GET {resource} -> HTTP {r.status_code} {msg}{hint}",
                               status_code=r.status_code, code=code)
        try:
            body = r.json()
        except ValueError as exc:
            raise PanRestError(f"GET {resource} returned non-JSON ({len(r.text)} bytes)",
                               status_code=r.status_code) from exc
        status = body.get("@status")
        if status is not None and status != "success":
            raise PanRestError(f"GET {resource} -> status {status}: {body.get('message', '')}",
                               status_code=r.status_code, code=str(body.get("@code", "")))
        return body.get("result", body)

    def entries(self, resource: str, **kwargs: Any) -> List[Dict[str, Any]]:
        """Like get(), but returns just the entry list (empty when none)."""
        result = self.get(resource, **kwargs)
        entry = result.get("entry", []) if isinstance(result, dict) else []
        if isinstance(entry, dict):  # single-entry responses are not wrapped in a list
            return [entry]
        return entry

    @staticmethod
    def _error_detail(r) -> tuple:
        try:
            body = r.json()
            return str(body.get("code", "")), body.get("message", r.text[:200])
        except ValueError:
            return None, r.text[:200]

    # -----------------------------------------------------------------------
    # Typed helpers (all read-only)
    # -----------------------------------------------------------------------

    def _objects(self, kind: str, location: str, device_group: Optional[str]) -> List[Dict[str, Any]]:
        if device_group:
            return self.entries(f"Objects/{kind}", device_group=device_group)
        return self.entries(f"Objects/{kind}", location=location)

    def list_addresses(self, location: str = "shared",
                       device_group: Optional[str] = None) -> List[Dict[str, Any]]:
        return self._objects("Addresses", location, device_group)

    def list_address_groups(self, location: str = "shared",
                            device_group: Optional[str] = None) -> List[Dict[str, Any]]:
        return self._objects("AddressGroups", location, device_group)

    def list_services(self, location: str = "shared",
                      device_group: Optional[str] = None) -> List[Dict[str, Any]]:
        return self._objects("Services", location, device_group)

    def list_service_groups(self, location: str = "shared",
                            device_group: Optional[str] = None) -> List[Dict[str, Any]]:
        return self._objects("ServiceGroups", location, device_group)

    def list_tags(self, location: str = "shared",
                  device_group: Optional[str] = None) -> List[Dict[str, Any]]:
        return self._objects("Tags", location, device_group)

    def list_security_pre_rules(self, device_group: str) -> List[Dict[str, Any]]:
        return self.entries("Policies/SecurityPreRules", device_group=device_group)

    def list_security_post_rules(self, device_group: str) -> List[Dict[str, Any]]:
        return self.entries("Policies/SecurityPostRules", device_group=device_group)

    def list_nat_pre_rules(self, device_group: str) -> List[Dict[str, Any]]:
        return self.entries("Policies/NATPreRules", device_group=device_group)

    def list_device_groups(self) -> List[str]:
        return sorted(e.get("@name", "") for e in self.entries("Panorama/DeviceGroups"))

    # -----------------------------------------------------------------------
    # Configuration export (XML API type=export; the one XML read besides
    # keygen that a report/log/export-only role permits)
    # -----------------------------------------------------------------------

    def export_configuration(self) -> bytes:
        """The full running configuration as raw XML bytes (root <config>).

        Uses the XML API's type=export, not /restapi/, because no REST
        equivalent exists; it is still a pure read. NOTE: the export contains
        the ENTIRE config, including mgt-config with admin password hashes;
        treat the saved file like a credential store.
        """
        r = self.session.get(f"{self.env.url}/api/",
                             params={"type": "export", "category": "configuration"},
                             headers={"X-PAN-KEY": self.api_key},
                             timeout=max(self.timeout, 120))
        if r.status_code >= 400:
            raise PanRestError(f"export failed: HTTP {r.status_code} {r.text[:200]}",
                               status_code=r.status_code)
        try:
            root = ET.fromstring(r.content)
        except ET.ParseError as exc:
            raise PanRestError("export returned unparseable XML") from exc
        if root.tag == "response":
            msg = "; ".join(l.text for l in root.iter("line") if l.text) or r.text[:200]
            raise PanRestError(f"export refused: {msg}", status_code=r.status_code,
                               code=root.get("code"))
        if root.tag != "config":
            raise PanRestError(f"export returned unexpected root <{root.tag}>")
        return r.content
