#!/usr/bin/env python3
"""app/palo/pan_env.py

One place that answers "which Panorama, and how do we authenticate to it?"

Both Panorama clients read their settings from here:
  - app/palo/panorama_api_client.py  (raw XML API over requests)
  - app/palo/panos_client.py         (pan-os-python object model)

and so does tools/pan/panorama_auth.py. Keeping the lookup here means the
lab's historical variable names and the canonical PANORAMA_* names are
honoured identically everywhere.

Environment variables (first match wins):

  host      panorama | ppanorama | PANORAMA_URL | PANORAMA_HOST
  port      PANORAMA_PORT                                   (default 443;
                                                             a :port in the
                                                             host wins)
  api key   PANORAMA_API_KEY | ppanorama_api_key
  username  PANORAMA_USERNAME | ppanorama_username | vm_username
  password  PANORAMA_PASSWORD | ppanorama_password | vm_password
  TLS       PANORAMA_TLS_VERIFY                             (default true;
                                                             "false" disables
                                                             certificate
                                                             verification)

Secrets never leave this module in log output: PanoramaEnv.describe() reports
WHICH variable supplied each value, never the value.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Mapping, Optional, Tuple
from urllib.parse import urlsplit

HOST_VARS = ("panorama", "ppanorama", "PANORAMA_URL", "PANORAMA_HOST")
API_KEY_VARS = ("PANORAMA_API_KEY", "ppanorama_api_key")
USERNAME_VARS = ("PANORAMA_USERNAME", "ppanorama_username", "vm_username")
PASSWORD_VARS = ("PANORAMA_PASSWORD", "ppanorama_password", "vm_password")
TLS_VERIFY_VAR = "PANORAMA_TLS_VERIFY"
PORT_VAR = "PANORAMA_PORT"

REPO_ROOT = Path(__file__).resolve().parents[2]


class PanoramaEnvError(RuntimeError):
    """Raised when .env does not describe a usable Panorama target."""


def load_repo_env(env_path: Optional[Path] = None) -> Path:
    """Load <repo>/.env into os.environ without overriding variables that are
    already set (same policy as nsx.cli_bootstrap.init_cli). Returns the path
    that was consulted, whether or not it existed."""
    from dotenv import load_dotenv  # local import: keeps this module importable without dotenv

    path = env_path or (REPO_ROOT / ".env")
    load_dotenv(dotenv_path=path, override=False)
    return path


def _first(environ: Mapping[str, str], names: Tuple[str, ...]) -> Tuple[Optional[str], Optional[str]]:
    """(value, var_name) for the first non-empty variable in `names`."""
    for name in names:
        value = environ.get(name)
        if value is not None and value.strip():
            return value.strip(), name
    return None, None


def _split_host(raw: str, default_port: int) -> Tuple[str, int, str]:
    """Normalise a host setting to (hostname, port, scheme). Accepts a bare
    hostname, host:port, or a full http(s) URL."""
    raw = raw.strip().rstrip("/")
    if "://" not in raw:
        raw = f"https://{raw}"
    parts = urlsplit(raw)
    if not parts.hostname:
        raise PanoramaEnvError(f"Panorama host setting is not a hostname or URL: {raw!r}")
    scheme = parts.scheme or "https"
    return parts.hostname, parts.port or default_port, scheme


@dataclass(frozen=True)
class PanoramaEnv:
    hostname: str
    port: int
    scheme: str
    verify: bool
    api_key: Optional[str]
    username: Optional[str]
    password: Optional[str]
    sources: Dict[str, Optional[str]]   # field -> env var that supplied it (values are never stored here)

    @property
    def url(self) -> str:
        default = 443 if self.scheme == "https" else 80
        host = self.hostname if self.port == default else f"{self.hostname}:{self.port}"
        return f"{self.scheme}://{host}"

    @property
    def has_api_key(self) -> bool:
        return bool(self.api_key)

    @property
    def has_password_auth(self) -> bool:
        return bool(self.username and self.password)

    def describe(self) -> Dict[str, object]:
        """Safe-to-log summary: hostnames and variable NAMES only."""
        return {
            "url": self.url,
            "hostname": self.hostname,
            "port": self.port,
            "tls_verify": self.verify,
            "auth": "api_key" if self.has_api_key else ("username_password" if self.has_password_auth else "none"),
            "username": self.username,
            "sources": dict(self.sources),
        }


def resolve_panorama_env(
    environ: Optional[Mapping[str, str]] = None,
    *,
    require_auth: bool = True,
) -> PanoramaEnv:
    """Build a PanoramaEnv from the environment (os.environ by default).

    Raises PanoramaEnvError when no host is set, or (with require_auth) when
    neither an API key nor a username/password pair is available.
    """
    env = environ if environ is not None else os.environ

    host_raw, host_var = _first(env, HOST_VARS)
    if not host_raw:
        raise PanoramaEnvError(
            "Panorama host not set in .env (looked for " + ", ".join(HOST_VARS) + ")."
        )

    port_raw, port_var = _first(env, (PORT_VAR,))
    try:
        default_port = int(port_raw) if port_raw else 443
    except ValueError as exc:
        raise PanoramaEnvError(f"{PORT_VAR} is not an integer: {port_raw!r}") from exc
    hostname, port, scheme = _split_host(host_raw, default_port)

    verify_raw, verify_var = _first(env, (TLS_VERIFY_VAR,))
    verify = (verify_raw or "true").lower() not in ("false", "0", "no", "off")

    api_key, key_var = _first(env, API_KEY_VARS)
    username, user_var = _first(env, USERNAME_VARS)
    password, pass_var = _first(env, PASSWORD_VARS)

    resolved = PanoramaEnv(
        hostname=hostname,
        port=port,
        scheme=scheme,
        verify=verify,
        api_key=api_key,
        username=username,
        password=password,
        sources={
            "host": host_var,
            "port": port_var,
            "tls_verify": verify_var,
            "api_key": key_var,
            "username": user_var,
            "password": pass_var,
        },
    )

    if require_auth and not (resolved.has_api_key or resolved.has_password_auth):
        raise PanoramaEnvError(
            "No Panorama credentials in .env: set " + " or ".join(API_KEY_VARS)
            + ", or a username/password pair from " + ", ".join(USERNAME_VARS)
            + " / " + ", ".join(PASSWORD_VARS) + "."
        )
    return resolved
