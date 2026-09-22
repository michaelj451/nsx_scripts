"""Interactive checkpoints shared by the NSX push and revert commands."""
from __future__ import annotations

import logging
from datetime import datetime, timezone


class ApplyBatch:
    def __init__(self, enabled: bool, logger: logging.Logger, initial_size=None):
        if initial_size not in (None, 1):
            raise ValueError("Apply must start with batch size 1; increase it at the interactive prompt.")
        self.enabled = enabled
        self.log = logger
        self.size = 1
        self.total = 0
        self.pending = []
        self.stopped = False
        self.decisions = []
        if enabled:
            self.log.info("APPLY starts with 1 object. At checkpoints: Enter=continue, "
                          "number=change batch size, n=reset to 1, x=stop.")

    def before_write(self) -> bool:
        """Ask before the next write, so a completed run needs no extra prompt."""
        if self.stopped:
            return False
        if not self.enabled or len(self.pending) < self.size:
            return True
        self.log.info("BATCH REVIEW: %d applied (%d total)", len(self.pending), self.total)
        for label in self.pending:
            self.log.info("  %s", label)
        while True:
            prompt = (f"Next batch [{self.size}]: Enter=continue, number=new size, "
                      "n=reset to 1, x=stop: ")
            try:
                answer = input(prompt).strip().lower()
            except (EOFError, KeyboardInterrupt):
                answer = "input_closed"
            before = self.size
            if answer in ("x", "exit", "q", "quit", "input_closed"):
                self.stopped = True
                decision = "input_closed" if answer == "input_closed" else "exit"
            elif answer in ("", "y", "yes"):
                decision = "approve"
            elif answer in ("n", "no"):
                self.size = 1
                decision = "reset_to_1"
            else:
                try:
                    new_size = int(answer)
                    if new_size < 1:
                        raise ValueError
                except ValueError:
                    self.log.warning("Enter a positive batch size, Enter, n or x.")
                    continue
                self.size = new_size
                decision = "resize"
            self.decisions.append({
                "ts": datetime.now(timezone.utc).isoformat(),
                "applied_count": self.total, "decision": decision,
                "batch_size_before": before, "batch_size_after": self.size,
            })
            if self.stopped:
                self.log.warning("APPLY STOPPED after %d objects (%s); no further writes.",
                                 self.total, decision)
                return False
            self.log.info("Operator decision: %s; next batch size=%d", decision, self.size)
            self.pending.clear()
            return True

    def record(self, row: dict) -> None:
        if not self.enabled:
            return
        self.total += 1
        name = row.get("display_name") or row.get("id") or row.get("rule_id") or "object"
        detail = f"{name}: {row.get('status', 'applied')}"
        if "ips_added" in row or "ips_removed" in row:
            detail += f"; IPs +{len(row.get('ips_added') or [])}/-{len(row.get('ips_removed') or [])}"
        if "refs_added_total" in row:
            detail += f"; refs +{row['refs_added_total']}"
        self.pending.append(detail)

    def totals(self) -> dict:
        return {
            "interactive_mode": self.enabled,
            "interactive_batch_size_initial": 1 if self.enabled else 0,
            "interactive_batch_size_final": self.size if self.enabled else 0,
            "interactive_exit_requested": self.stopped,
        }
