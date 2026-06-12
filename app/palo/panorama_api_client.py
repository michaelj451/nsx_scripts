"""app/palo/panorama_api_client.py

Thin Panorama XML API client.

Reads credentials from .env (PANORAMA_URL + either PANORAMA_API_KEY
or PANORAMA_USERNAME+PANORAMA_PASSWORD). All requests use the legacy XML
API since it has 100% coverage of config operations on PAN-OS 10.x/11.x.

Design properties:
- The class instance enforces TLS verification toggle via PANORAMA_TLS_VERIFY
  (defaults to TRUE; set to "false" in .env for self-signed lab Panoramas).
- Every method either returns the parsed XML element tree or raises
  PanoramaApiError on failure.
- The client is "thin" — no retry, no backoff, no caching. Callers compose
  higher-level workflows.
- Writes go to CANDIDATE config (not committed). A separate commit() call
  is required to push to the running config.

API surface:
    PanoramaClient.from_env() -> PanoramaClient
    .get_config(xpath: str) -> Element
    .set_config(xpath: str, element_str: str) -> Element     # MERGE / APPEND
    .edit_config(xpath: str, element_str: str) -> Element    # REPLACE
    .delete_config(xpath: str) -> Element
    .commit(description: Optional[str] = None) -> dict
    .op(cmd: str) -> Element                                  # operational mode
"""
from __future__ import annotations

import logging
import os
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import urllib3
import requests

# Lab Panoramas commonly use self-signed certs — let the operator opt out of
# verification via PANORAMA_TLS_VERIFY=false. When that happens, suppress the
# noisy InsecureRequestWarning emitted on every request.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)


class PanoramaApiError(Exception):
    """Raised when the Panorama API returns a non-success response."""
    def __init__(self, status_code: int, code: Optional[str], message: str):
        self.status_code = status_code
        self.code = code
        super().__init__(f"[HTTP {status_code} / pan-code {code}] {message}")


@dataclass
class PanoramaClient:
    base_url: str
    api_key:  str
    verify:   bool = True
    timeout:  int  = 60

    # -----------------------------------------------------------------------
    # Construction
    # -----------------------------------------------------------------------

    @classmethod
    def from_env(cls) -> "PanoramaClient":
        """Construct from .env. Honors the lab's existing naming convention:

            ppanorama      = pano4.lab.local           (hostname or URL)
            vm_username    = <username>                 (shared with VM tagging)
            vm_password    = <password>

        Also accepts canonical variants when present:
            PANORAMA_URL, PANORAMA_USERNAME, PANORAMA_PASSWORD
            PANORAMA_API_KEY                            (preferred when set)
            PANORAMA_TLS_VERIFY=false                   (defaults to true)
        """
        host = (os.environ.get("panorama")
                or os.environ.get("ppanorama")
                or os.environ.get("PANORAMA_URL")
                or os.environ.get("PANORAMA_HOST"))
        if not host:
            raise PanoramaApiError(
                status_code=0, code=None,
                message="Panorama host not set in .env (looked for "
                        "ppanorama, PANORAMA_URL, PANORAMA_HOST).",
            )
        # Normalize to https://<host>
        host = host.strip().rstrip("/")
        if not host.startswith(("http://", "https://")):
            host = f"https://{host}"
        verify = os.environ.get("PANORAMA_TLS_VERIFY", "true").lower() != "false"

        # Prefer API key when present (avoids round-tripping the password each run)
        api_key = (os.environ.get("PANORAMA_API_KEY")
                   or os.environ.get("ppanorama_api_key"))
        if not api_key:
            username = (os.environ.get("PANORAMA_USERNAME")
                        or os.environ.get("ppanorama_username")
                        or os.environ.get("vm_username"))
            password = (os.environ.get("PANORAMA_PASSWORD")
                        or os.environ.get("ppanorama_password")
                        or os.environ.get("vm_password"))
            if not (username and password):
                raise PanoramaApiError(
                    status_code=0, code=None,
                    message=("No PANORAMA_API_KEY and no "
                             "PANORAMA_USERNAME/PANORAMA_PASSWORD nor "
                             "vm_username/vm_password in .env."),
                )
            log.info("Generating Panorama API key for user %r ...", username)
            api_key = cls._keygen(host, username, password, verify)
        return cls(base_url=host, api_key=api_key, verify=verify)

    # -----------------------------------------------------------------------
    # Low-level transport
    # -----------------------------------------------------------------------

    @staticmethod
    def _keygen(url: str, username: str, password: str, verify: bool) -> str:
        params = {"type": "keygen", "user": username, "password": password}
        r = requests.get(f"{url}/api/", params=params, verify=verify, timeout=60)
        r.raise_for_status()
        root = ET.fromstring(r.text)
        if root.get("status") != "success":
            code = root.get("code")
            msg = (root.findtext("./msg/line") or root.findtext("./msg") or r.text)
            raise PanoramaApiError(status_code=r.status_code, code=code,
                                   message=f"keygen failed: {msg}")
        key = root.findtext("./result/key")
        if not key:
            raise PanoramaApiError(status_code=r.status_code, code=None,
                                   message=f"keygen returned no key: {r.text[:200]}")
        return key

    def _request(self, params: Dict[str, str]) -> ET.Element:
        """Send a request and return the parsed XML <response>. Raises
        PanoramaApiError if status != 'success'."""
        params = {**params, "key": self.api_key}
        r = requests.get(
            f"{self.base_url}/api/", params=params,
            verify=self.verify, timeout=self.timeout,
        )
        # PAN always returns 200 even on logical failure; the XML status attr is
        # the source of truth. But check HTTP-level errors too.
        if r.status_code >= 400:
            raise PanoramaApiError(status_code=r.status_code, code=None,
                                   message=f"HTTP error: {r.text[:300]}")
        try:
            root = ET.fromstring(r.text)
        except ET.ParseError as exc:
            raise PanoramaApiError(status_code=r.status_code, code=None,
                                   message=f"non-XML response: {r.text[:300]}") from exc
        if root.get("status") != "success":
            code = root.get("code")
            msg_parts = [el.text for el in root.iter("line") if el.text]
            msg = "; ".join(msg_parts) or (root.findtext("./msg") or r.text[:300])
            raise PanoramaApiError(status_code=r.status_code, code=code, message=msg)
        return root

    # -----------------------------------------------------------------------
    # Config API — type=config
    # -----------------------------------------------------------------------

    def get_config(self, xpath: str) -> ET.Element:
        """GET an xpath from CANDIDATE config. Returns the <response>'s
        <result> sub-element (or its first child if there's just one)."""
        root = self._request({"type": "config", "action": "get", "xpath": xpath})
        return root.find("./result") or root

    def set_config(self, xpath: str, element_str: str) -> ET.Element:
        """SET an element at xpath — MERGES with existing siblings. For repeated
        elements like <member>, set is additive (appends). For single elements
        (e.g. <action>), set replaces.

        Writes to CANDIDATE config. A subsequent commit() pushes to running.

        element_str: literal XML, e.g. '<member>svc-https</member>'.
        """
        root = self._request({
            "type": "config", "action": "set",
            "xpath": xpath, "element": element_str,
        })
        return root

    def edit_config(self, xpath: str, element_str: str) -> ET.Element:
        """EDIT (= REPLACE) the element at xpath with the supplied content.

        Writes to CANDIDATE config.
        """
        root = self._request({
            "type": "config", "action": "edit",
            "xpath": xpath, "element": element_str,
        })
        return root

    def delete_config(self, xpath: str) -> ET.Element:
        root = self._request({"type": "config", "action": "delete", "xpath": xpath})
        return root

    # -----------------------------------------------------------------------
    # Commit — push CANDIDATE → RUNNING
    # -----------------------------------------------------------------------

    def commit(self, description: Optional[str] = None) -> Dict[str, Any]:
        """Submit a commit job. Returns {"jobid": str, "message": str}.

        Caller should poll commit_status(jobid) for completion.
        """
        cmd = "<commit>"
        if description:
            # PAN expects <description> nested under <commit>
            desc_escaped = description.replace("<", "&lt;").replace(">", "&gt;")
            cmd += f"<description>{desc_escaped}</description>"
        cmd += "</commit>"
        root = self._request({"type": "commit", "cmd": cmd})
        jobid = root.findtext("./result/job") or ""
        msg = root.findtext("./msg/line") or root.findtext("./msg") or ""
        return {"jobid": jobid, "message": msg}

    def commit_status(self, jobid: str) -> Dict[str, Any]:
        cmd = f"<show><jobs><id>{jobid}</id></jobs></show>"
        root = self._request({"type": "op", "cmd": cmd})
        return {
            "status":   root.findtext("./result/job/status"),
            "progress": root.findtext("./result/job/progress"),
            "result":   root.findtext("./result/job/result"),
            "details":  [(el.text or "") for el in root.iter("line")],
        }

    # -----------------------------------------------------------------------
    # Operational API — type=op
    # -----------------------------------------------------------------------

    def op(self, cmd_xml: str) -> ET.Element:
        """Send an operational-mode XML command."""
        root = self._request({"type": "op", "cmd": cmd_xml})
        return root


# =============================================================================
# Convenience helpers for common config xpaths
# =============================================================================

def shared_pre_rules_xpath() -> str:
    return "/config/shared/pre-rulebase/security/rules"


def shared_post_rules_xpath() -> str:
    return "/config/shared/post-rulebase/security/rules"


def dg_pre_rules_xpath(dg_name: str) -> str:
    return ("/config/devices/entry[@name='localhost.localdomain']"
            f"/device-group/entry[@name='{dg_name}']"
            "/pre-rulebase/security/rules")


def dg_post_rules_xpath(dg_name: str) -> str:
    return ("/config/devices/entry[@name='localhost.localdomain']"
            f"/device-group/entry[@name='{dg_name}']"
            "/post-rulebase/security/rules")


def rule_service_xpath(rules_xpath: str, rule_name: str) -> str:
    """The xpath to a rule's <service> element. SET-ing a <member>X</member>
    here APPENDS X to the rule's service list."""
    return f"{rules_xpath}/entry[@name='{rule_name}']/service"


def shared_services_xpath() -> str:
    return "/config/shared/service"
