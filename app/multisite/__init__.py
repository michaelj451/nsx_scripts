"""app/multisite: three-site (or N-site) migration planning, kept separate
from the two-site workflow code on purpose.

    plan.py        which sibling views each manager needs, coverage, mapped
                   addresses that land on machines already in use, the
                   addresses each site must keep reserved, and the ordered
                   (print-only) commands
    palo_tags.py   the Palo Alto tag plan: per-VM address objects tagged with
                   hostname and asl_id, one dynamic address group per NSX
                   group (hostname tags up to a size threshold, a unique
                   security_group tag above it)

Pure functions over files the caller already has: no NSX or Panorama calls.
"""
