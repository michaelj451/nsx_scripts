"""app/common: vendor-neutral helpers shared by the NSX and Palo Alto tools.

Rules for every module in this package:

  * Never import nsx.* or palo.*. The vendor packages import common, never
    the reverse, so a PAN tool can use these helpers without pulling in the
    NSX client (app/utilities/file_utilities.py cannot be used that way: it
    imports NsxPolicyClient at the top).
  * No import-time side effects. Importing a module here never reads .env,
    creates a directory, opens a log file or touches the network. Callers do
    those things explicitly, when they choose to.
  * Standard library plus PyYAML only.

Modules:
    timeutil    UTC run timestamps and ISO strings
    paths       repo root, env-driven directories, filesystem-safe names
    fileio      JSON / YAML / JSONL / CSV / text IO, atomic writes, SHA-256
    logs        UTC log formatter and per-tool file + console logging
    bundles     timestamped run directories, `latest` pointer, retention
    ipspan      IPv4/IPv6 address spans (hosts, CIDRs, ranges) as intervals
    subnet_map  old_subnet -> new_subnet CSV maps, one or more target sites
    md          markdown tables and table alignment

Existing scripts are not migrated to these modules yet; they keep their own
copies until each one is moved over deliberately and re-tested.
"""
