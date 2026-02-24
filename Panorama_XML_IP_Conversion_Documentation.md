# Panorama XML IP Conversion Tool

Additive address + zone injection utility

------------------------------------------------------------------------

## Purpose

This tool:

-   Reads a Panorama `running-config.xml`
-   Converts IPs, subnets, and ranges based on a CSV mapping file
-   Creates new address objects for mapped values
-   Adds new object references to rules (additive only)
-   Adds new zones to device-group rules only
-   Does NOT remove existing rule members
-   Does NOT remove existing zones

Shared rules are not zone-modified.

------------------------------------------------------------------------

## Required Input Files

### 1) Panorama Configuration Export

Export full configuration from Panorama:

GUI: Panorama → Setup → Operations → Export named configuration snapshot

Save as:

    running-config.xml

------------------------------------------------------------------------

### 2) IP Mapping CSV

Format:

    search_ip,new_ip,new_object_name,tags,desc
    10.1.1.0/24,10.1.2.0/24,,,something1
    10.2.1.0/24,10.2.2.0/24,,,something2
    4.2.0.0/16,4.4.0.0/16,,,something5

Rules:

-   `search_ip` must be a valid subnet
-   `new_ip` must be same IP version
-   Mapping is containment-based (IPs inside search_ip are offset into
    new_ip)
-   Ranges must be fully contained to be mapped

------------------------------------------------------------------------

### 3) Device Group → Zone Mapping File

Example:

    # Device Group to Zone Mapping
    dg-3: zone-3-new
    dg-4: zone-4-new
    dg-5: zone-5-new
    dg-6: zone-6-new

Rules:

-   Only device-group rules are zone-modified
-   Shared rules are not modified
-   Zones are added (never removed)

------------------------------------------------------------------------

# How To Run the Script

From your virtual environment:

    python pa_xml_zone.py \
      --config running-config.xml \
      --csv ip_map.csv \
      --dg dg_zone.txt \
      --out converted.xml \
      --changelog changes.json

After successful run:

    Wrote: converted.xml
    Changelog: changes.json (XX changes)

------------------------------------------------------------------------

# Pretty Formatting (Recommended)

Panorama does not care about whitespace, but humans do.

Format original:

    xmllint --format running-config.xml > original.pretty.xml

Format converted:

    xmllint --format converted.xml > converted.pretty.xml

------------------------------------------------------------------------

# Compare Original vs Converted

    diff -u original.pretty.xml converted.pretty.xml

Expected results:

-   Only added `<member>` lines
-   Only added `<entry name="svb_m1_...">` address objects
-   Only added `<member>zone-*-new</member>` inside device-group rules
-   No removed lines (except XML header encoding difference)

------------------------------------------------------------------------

# Validate XML Before Import

Validate structure:

    xmllint --noout converted.xml

If no output appears, XML is valid.

Count new objects:

    grep -c "svb_m1_" converted.pretty.xml

Confirm zones only added in device groups:

    grep -n "zone-3-new" converted.pretty.xml

Make sure results appear under:

    /devices/entry/device-group/entry

Not under `/shared`.

------------------------------------------------------------------------

# Import Back Into Panorama (Lab First)

Panorama → Setup → Operations → Import named configuration snapshot\
Load and commit in lab before production.

------------------------------------------------------------------------

# Behavior Summary

Additive only:

-   Original members remain
-   Original zones remain
-   New objects appended
-   New rule members appended
-   Device-group zones appended
-   No deletions

Containment-based mapping:

If an IP/range/subnet is inside a mapped `search_ip`, it is offset into
the corresponding `new_ip`.

Example:

10.1.1.5 → 10.1.2.5\
10.4.1.5-10.4.1.20 → 10.4.2.5-10.4.2.20



python pa_xml_zone_optimized.py --config test_cases/test10.xml --csv ip_map.txt --dg dg_zone.txt --out mike_config.xml --changelog mike_changelog.jsonl


python pa_xml_zone.py --config test_cases/test10.xml --csv ip_map.txt --dg dg_zone.txt --out bharat_config.xml --changelog bharac_changelog.json 

python pa_xml_zone-orig.py --config test_cases/test10.xml --csv ip_map.txt --dg dg_zone.txt --out bharat-orig.xml  


python pa_xml_zone_range_optimized.py --config test_cases/test10.xml --csv ip_map.txt --dg dg_zone.txt --out mike_range_config.xml --changelog mike_range_changelog.jsonl