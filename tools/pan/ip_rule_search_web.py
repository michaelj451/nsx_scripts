#!/usr/bin/env python3
"""tools/pan/ip_rule_search_web.py

Superseded by the SSDD Toolkit hub, which serves the IP Rule Search page at
/ip-search plus the other tool pages. This shim just launches the toolkit
so existing commands keep working:

    python tools/pan/ip_rule_search_web.py --user-env agent_user \
        --password-env agent_password --no-tls-verify

See tools/pan/ssdd_toolkit_web.py for the real implementation.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ssdd_toolkit_web import main  # noqa: E402

if __name__ == "__main__":
    print("Note: this tool is now the SSDD Toolkit; launching the hub "
          "(IP Rule Search lives at /ip-search).", file=sys.stderr)
    sys.exit(main())
