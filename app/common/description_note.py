"""app/common/description_note.py

Change-record note appended to the description of every object a workflow
writes (Mike, 2026-10-14: "Ticket #, Username, Date ... appended to whatever we
touch"). Vendor-neutral: the NSX push tools and the Palo plan both use it.

The note is appended once, in square brackets, after any existing text:

    IP-only sibling of web [Ticket CHG0012345 | mxferguson | 2026-10-14]

When the result would be longer than the target's limit, the existing text is
shortened (ending in "...") and the note is kept whole.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

NSX_DESCRIPTION_MAX = 1024
PAN_DESCRIPTION_MAX = 1023


def change_note(ticket: Optional[str], user: Optional[str], date: Optional[str]) -> str:
    """"Ticket <#> | <user> | <date>"; a missing ticket reads "none"."""
    return " | ".join([f"Ticket {ticket or 'none'}"] + [v for v in (user, date) if v])


def append_note(text: Optional[str], note: Optional[str], limit: int = NSX_DESCRIPTION_MAX) -> str:
    text = (text or "").strip()
    if not note:
        return text
    tag = f"[{note}]"
    if tag in text:
        return text
    room = limit - len(tag) - 1
    if room <= 3:
        return tag[:limit]
    if len(text) > room:
        text = text[:room - 3].rstrip() + "..."
    return f"{text} {tag}" if text else tag


def with_note(obj: Dict[str, Any], note: Optional[str], field: str = "description",
              limit: int = NSX_DESCRIPTION_MAX) -> Dict[str, Any]:
    """A copy of `obj` with the note appended to `field`; `obj` itself when there is no note."""
    if not note:
        return obj
    out = dict(obj)
    out[field] = append_note(obj.get(field), note, limit)
    return out
