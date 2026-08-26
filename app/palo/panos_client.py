#!/usr/bin/env python3
"""app/palo/panos_client.py

Panorama client built on pan-os-python (the `panos` package). This is the
Palo Alto counterpart of app/nsx/nsx_policy_client.py: one typed object that
knows how to reach a Panorama, authenticate, and expose the pan-os-python
object model for tools to build on.

Two Panorama clients exist on purpose:

  app/palo/panorama_api_client.py   raw XML API over `requests`; xpath-level
                                    get/set/edit/delete and commit. Use it for
                                    surgical config edits and config pulls.
  app/palo/panos_client.py          THIS FILE. pan-os-python object model
                                    (DeviceGroup, AddressObject, SecurityRule
                                    ...). Use it for anything that reasons
                                    about objects rather than xpaths.

Both read their target and credentials through app/palo/pan_env.py, so the
same .env works for either.

Design properties (mirrors NsxPolicyClient):
  - from_env() is the only constructor tools should use.
  - This module itself is READ-ONLY. It exposes `device` (a panos Panorama)
    for tools that need to write; those tools own their own --apply gate,
    baseline capture, and report writing.
  - TLS verification follows PANORAMA_TLS_VERIFY (default true). Disabling it
    is scoped to this client's connection via an ssl_context, not global
    monkey-patching.
  - Credentials are never logged. api_key_fingerprint() gives a safe handle
    for reports.
  - Errors surface as PanosClientError with the underlying panos error chained.

API surface:
    PanosClient.from_env(environ=None, load_env=True) -> PanosClient
    .env                       -> PanoramaEnv (safe .describe())
    .device                    -> panos.panorama.Panorama (lazy)
    .connect()                 -> dict   system info, verifies auth
    .api_key                   -> str    generates via keygen when only user/pass given
    .api_key_fingerprint()     -> str    sha256 prefix, safe for logs
    .verify_api_key()          -> bool   True if the current key is accepted
    .system_info()             -> dict   raw "show system info" -> system
    .list_device_groups()      -> list[str]
    .list_templates()          -> list[str]
    .list_template_stacks()    -> list[str]
    .op(cmd, xml=True)         -> xml.etree Element
"""
from __future__ import annotations

import hashlib
import logging
import ssl
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

from palo.pan_env import PanoramaEnv, PanoramaEnvError, load_repo_env, resolve_panorama_env

try:
    from panos import errors as panos_errors
    from panos.base import PanDevice
    from panos.panorama import DeviceGroup, Panorama, Template, TemplateStack
    _PANOS_IMPORT_ERROR: Optional[Exception] = None
except ImportError as exc:  # pragma: no cover - exercised only when the dependency is missing
    panos_errors = None
    PanDevice = None
    DeviceGroup = Panorama = Template = TemplateStack = None
    _PANOS_IMPORT_ERROR = exc

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 60


class PanosClientError(RuntimeError):
    """Raised for any failure talking to Panorama through pan-os-python."""


def _require_panos() -> None:
    if _PANOS_IMPORT_ERROR is not None:
        raise PanosClientError(
            "pan-os-python is not installed. Install with: "
            "pip install -r docker/requirements-pip.txt  (pins pan-os-python)"
        ) from _PANOS_IMPORT_ERROR


if PanDevice is not None:

    class VerifyAwarePanorama(Panorama):
        """panos.panorama.Panorama that can carry an ssl_context down to the
        underlying pan.xapi.PanXapi, so PANORAMA_TLS_VERIFY=false affects only
        this connection. pan-os-python builds its transport in two places
        (generate_xapi for normal calls, _retrieve_api_key for keygen); both
        are overridden here to pass the context through."""

        def __init__(self, *args: Any, ssl_context: Optional[ssl.SSLContext] = None, **kwargs: Any) -> None:
            self._ssl_context = ssl_context
            super().__init__(*args, **kwargs)

        def _xapi_kwargs(self) -> Dict[str, Any]:
            kwargs: Dict[str, Any] = {
                "hostname": self.hostname,
                "port": self.port,
                "timeout": self.timeout,
                "pan_device": self,
            }
            if self._ssl_context is not None:
                kwargs["ssl_context"] = self._ssl_context
            return kwargs

        def generate_xapi(self):  # type: ignore[override]
            return PanDevice.XapiWrapper(api_key=self.api_key, **self._xapi_kwargs())

        def _retrieve_api_key(self):  # type: ignore[override]
            self._logger.debug("Getting API key from %s for user %s", self.hostname, self._api_username)
            xapi = PanDevice.XapiWrapper(
                api_username=self._api_username,
                api_password=self._api_password,
                **self._xapi_kwargs(),
            )
            xapi.keygen(retry_on_peer=False)
            return xapi.api_key

else:  # pragma: no cover
    VerifyAwarePanorama = None  # type: ignore[assignment,misc]


def _unverified_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


@dataclass
class PanosClient:
    env: PanoramaEnv
    timeout: int = DEFAULT_TIMEOUT_SECONDS
    _device: Any = field(default=None, repr=False)
    _system_info: Optional[Dict[str, Any]] = field(default=None, repr=False)

    # -----------------------------------------------------------------------
    # Construction
    # -----------------------------------------------------------------------

    @classmethod
    def from_env(
        cls,
        environ: Optional[Mapping[str, str]] = None,
        *,
        load_env: bool = True,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        device: Any = None,
    ) -> "PanosClient":
        """Build a client from .env (see app/palo/pan_env.py for the variables).

        `device` lets tests inject a fake Panorama; production callers leave it
        unset and the real pan-os-python device is created lazily.
        """
        if load_env and environ is None:
            load_repo_env()
        try:
            env = resolve_panorama_env(environ)
        except PanoramaEnvError as exc:
            raise PanosClientError(str(exc)) from exc
        return cls(env=env, timeout=timeout, _device=device)

    @property
    def device(self):
        """The pan-os-python Panorama object. Created on first use; no network
        traffic until a method on it is called."""
        if self._device is None:
            _require_panos()
            ctx = None if self.env.verify else _unverified_context()
            if not self.env.verify:
                log.warning("TLS certificate verification DISABLED for %s (PANORAMA_TLS_VERIFY=false)",
                            self.env.hostname)
            self._device = VerifyAwarePanorama(
                hostname=self.env.hostname,
                port=self.env.port,
                api_username=self.env.username if not self.env.api_key else None,
                api_password=self.env.password if not self.env.api_key else None,
                api_key=self.env.api_key,
                timeout=self.timeout,
                ssl_context=ctx,
            )
        return self._device

    # -----------------------------------------------------------------------
    # Authentication
    # -----------------------------------------------------------------------

    @property
    def api_key(self) -> str:
        """The API key in use. When .env only has a username/password this
        triggers a keygen call on first access."""
        try:
            return self.device.api_key
        except Exception as exc:  # panos raises several types; normalise them
            raise PanosClientError(f"API key generation failed for {self.env.url}: {exc}") from exc

    def api_key_fingerprint(self) -> str:
        """Short sha256 prefix of the key. Safe to put in logs and reports."""
        return hashlib.sha256(self.api_key.encode("utf-8")).hexdigest()[:12]

    def connect(self) -> Dict[str, Any]:
        """Authenticate and pull system info. Raises PanosClientError on any
        connectivity, TLS, or credential problem. Returns the parsed
        `show system info` -> system dict and caches it."""
        try:
            self.device.refresh_system_info()
            info = self.device.show_system_info()
        except Exception as exc:
            raise PanosClientError(self._explain(exc)) from exc
        system = info.get("system", info) if isinstance(info, dict) else {}
        self._system_info = system
        log.info("Connected to Panorama %s (hostname=%s serial=%s sw=%s)",
                 self.env.url, system.get("hostname"), system.get("serial"), system.get("sw-version"))
        return system

    def verify_api_key(self) -> bool:
        """True when the key is accepted by Panorama; False on an auth error.
        Other failures (DNS, TLS, timeout) still raise."""
        try:
            self.connect()
            return True
        except PanosClientError as exc:
            text = str(exc).lower()
            if "invalid credential" in text or "unauthorized" in text or "403" in text or "401" in text:
                return False
            raise

    # -----------------------------------------------------------------------
    # Read-only inventory
    # -----------------------------------------------------------------------

    def system_info(self, refresh: bool = False) -> Dict[str, Any]:
        if self._system_info is None or refresh:
            return self.connect()
        return self._system_info

    def list_device_groups(self) -> List[str]:
        return self._names(DeviceGroup)

    def list_templates(self) -> List[str]:
        return self._names(Template)

    def list_template_stacks(self) -> List[str]:
        return self._names(TemplateStack)

    def _names(self, cls) -> List[str]:
        _require_panos()
        try:
            objs = cls.refreshall(self.device, name_only=True, add=False)
        except Exception as exc:
            raise PanosClientError(self._explain(exc)) from exc
        return sorted(o.name for o in objs)

    def op(self, cmd: str, xml: bool = True):
        """Run an operational command. `xml=True` means `cmd` is CLI syntax
        ("show devices connected") and pan-os-python converts it to XML."""
        try:
            return self.device.op(cmd, xml=xml)
        except Exception as exc:
            raise PanosClientError(self._explain(exc)) from exc

    # -----------------------------------------------------------------------
    # Error explanation
    # -----------------------------------------------------------------------

    def _explain(self, exc: Exception) -> str:
        """Turn a panos / socket / ssl exception into an operator-facing line."""
        name = type(exc).__name__
        text = str(exc)
        lower = text.lower()
        where = self.env.url
        if "certificate" in lower or "ssl" in lower:
            return (f"TLS failure talking to {where}: {text}. If this Panorama uses a "
                    f"self-signed certificate, set PANORAMA_TLS_VERIFY=false in .env.")
        if "invalid credential" in lower:
            return f"Panorama rejected the credentials for {where} ({name}: {text})."
        if "name or service not known" in lower or "nodename nor servname" in lower or "getaddrinfo" in lower:
            return f"Cannot resolve Panorama host {self.env.hostname} ({name}: {text})."
        if "timed out" in lower or "timeout" in lower:
            return f"Timed out reaching {where} after {self.timeout}s ({name}: {text})."
        if "connection refused" in lower:
            return f"Connection refused by {where} ({name}: {text})."
        return f"{name} from {where}: {text}"
