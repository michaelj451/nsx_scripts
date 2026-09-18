from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.util import Inches, Pt

OUT = "docs/nsx/NSX_WORKFLOW_OVERVIEW.pptx"
prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)

NAVY = RGBColor(17, 35, 62)
BLUE = RGBColor(33, 111, 189)
TEAL = RGBColor(0, 150, 145)
ORANGE = RGBColor(235, 133, 45)
GREEN = RGBColor(39, 150, 91)
RED = RGBColor(190, 55, 55)
LIGHT = RGBColor(242, 246, 250)
MID = RGBColor(92, 108, 126)
WHITE = RGBColor(255, 255, 255)


def box(slide, x, y, w, h, fill=WHITE, line=None, radius=False):
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE if radius else MSO_SHAPE.RECTANGLE, Inches(x), Inches(y), Inches(w), Inches(h))
    shape.fill.solid(); shape.fill.fore_color.rgb = fill
    shape.line.color.rgb = line or fill
    return shape


def text(slide, value, x, y, w, h, size=18, color=NAVY, bold=False, align=PP_ALIGN.LEFT):
    tb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = tb.text_frame; tf.clear(); tf.word_wrap = True
    p = tf.paragraphs[0]; p.alignment = align
    r = p.add_run(); r.text = value; r.font.name = "Aptos"; r.font.size = Pt(size); r.font.bold = bold; r.font.color.rgb = color
    return tb


def title(slide, heading, sub=None):
    text(slide, heading, .55, .28, 12.2, .55, 28, NAVY, True)
    if sub: text(slide, sub, .58, .88, 12, .35, 11, MID)
    box(slide, .55, 1.22, 1.2, .06, TEAL)


def footer(slide, n):
    text(slide, f"NSX migration workflow  •  {n}/8", .58, 7.12, 12, .2, 9, MID)


def bullet_list(slide, items, x, y, w, size=16, color=NAVY, gap=.42):
    for i, item in enumerate(items):
        text(slide, "• " + item, x, y + i * gap, w, .32, size, color)

# 1
s = prs.slides.add_slide(prs.slide_layouts[6]); box(s, 0, 0, 13.333, 7.5, LIGHT)
box(s, 0, 0, 13.333, 1.0, NAVY); text(s, "NSX WORKFLOW", .65, .25, 8, .45, 30, WHITE, True)
text(s, "A short operating model for workflows A–D", .68, 1.65, 11.8, .7, 30, NAVY, True)
text(s, "Develop → test and report → implement safely", .7, 2.45, 10, .4, 20, TEAL, True)
for i, (label, desc, color) in enumerate([("A", "clone", BLUE), ("B", "in-place remap", ORANGE), ("C", "decompose", TEAL), ("D", "production remap", GREEN)]):
    x = .8 + i * 3.05; box(s, x, 4.05, 2.45, 1.4, WHITE, color, True); text(s, label, x+.18, 4.25, .5, .6, 34, color, True); text(s, desc, x+.75, 4.3, 1.5, .4, 17, NAVY, True)
text(s, "Purpose: move or adapt NSX security policy while preserving reviewability, rollback, and traffic safety.", .8, 6.25, 11.7, .45, 15, MID)
footer(s, 1)

# 2
s = prs.slides.add_slide(prs.slide_layouts[6]); box(s, 0, 0, 13.333, 7.5, WHITE); title(s, "What each workflow does", "Same controlled pattern; different target and change scope")
items = [("A", "Clone policy objects", "Copy services, groups, policies, and rules to a target LM; segments are stripped.", BLUE), ("B", "In-place remap", "Add mapped IPs to existing groups; groups-only, additive, and idempotent.", ORANGE), ("C", "AVS sibling groups", "Create IP-only sibling groups for the AVS target and amend rule references.", TEAL), ("D", "On-prem nonprod siblings", "Create mapped sibling groups for the standalone nonprod environment.", GREEN)]
for i, (letter, head, desc, color) in enumerate(items):
    y = 1.55 + i * 1.25; box(s, .75, y, .75, .75, color, color, True); text(s, letter, .75, y+.12, .75, .4, 27, WHITE, True, PP_ALIGN.CENTER); text(s, head, 1.8, y+.02, 3.3, .3, 17, NAVY, True); text(s, desc, 5.0, y+.02, 7.4, .55, 15, MID)
footer(s, 2)

# 3
s = prs.slides.add_slide(prs.slide_layouts[6]); box(s, 0, 0, 13.333, 7.5, LIGHT); title(s, "Phase 1 — Development", "Build and transform offline before any NSX write")
for i, (head, desc, color) in enumerate([("Capture", "Export current state and freeze the source inputs.", BLUE), ("Transform", "Build clone, sibling, or CSV-remap bundles.", TEAL), ("Review", "Inspect diffs, scope, exclusions, and rollback baseline.", ORANGE)]):
    x = .8 + i * 4.15; box(s, x, 1.8, 3.55, 2.0, WHITE, color, True); text(s, str(i+1), x+.2, 2.05, .45, .45, 26, color, True); text(s, head, x+.8, 2.08, 2.3, .35, 18, NAVY, True); text(s, desc, x+.25, 2.75, 3.0, .7, 15, MID)
text(s, "Guardrails", .85, 4.65, 2, .35, 18, NAVY, True)
bullet_list(s, ["Dry-run is the default; --apply is explicit.", "Inputs and outputs are timestamped and reviewable.", "Each environment is changed and verified independently."], .95, 5.15, 11, 17)
footer(s, 3)

# 4
s = prs.slides.add_slide(prs.slide_layouts[6]); box(s, 0, 0, 13.333, 7.5, WHITE); title(s, "Phase 2 — Testing & delivery reports", "Real reports show the proposed delta before approval and the result after apply")
for i, (head, desc, color) in enumerate([("Dry run", "Preview counts and diffs", BLUE), ("Apply", "Record created/changed/failed", TEAL), ("Verify", "Read-only live checks", GREEN)]):
    x = .8 + i*4.15; box(s, x, 1.55, 3.5, .85, color, color, True); text(s, head, x+.2, 1.75, 1.2, .3, 17, WHITE, True); text(s, desc, x+1.25, 1.75, 2.0, .3, 13, WHITE)
box(s, .8, 2.85, 11.75, 2.5, LIGHT, LIGHT, True); text(s, "Example: WF-C apply report", 1.1, 3.1, 4, .35, 18, NAVY, True)
for i, (num, label, color) in enumerate([("1", "created", BLUE), ("4", "changed", TEAL), ("0", "failed", GREEN), ("5 / 3", "IPs + / −", ORANGE), ("2", "rule refs +", NAVY)]):
    x = 1.1 + i*2.2; text(s, num, x, 3.75, 1.5, .5, 25, color, True); text(s, label, x, 4.35, 1.6, .35, 13, MID)
text(s, "Audit: network-group-8_np_ips created with 4 IPs; allow-icmp-network-8 gained 2 sibling references.", 1.1, 5.75, 11, .45, 15, NAVY)
footer(s, 4)

# 5
s = prs.slides.add_slide(prs.slide_layouts[6]); box(s, 0, 0, 13.333, 7.5, LIGHT); title(s, "Report example — Workflow B dry run", "Existing remap report used as the approval gate")
box(s, .75, 1.5, 5.75, 4.85, NAVY, NAVY, True); text(s, "CSV IP remap dry-run: nsx-gm1", 1.05, 1.82, 5.1, .35, 18, WHITE, True)
text(s, "Mode: DRY-RUN\nGroups: 13 seen • 13 dry-run • 0 failed\nIPs to add: 3 • removed: 0\nAdditive-only contract: PASS\nResult: CHANGES", 1.05, 2.55, 4.9, 2.0, 17, WHITE)
text(s, "Would add: 10.16.0.50, 10.16.0.51, 10.16.1.0/24\nFrom: 10.6.0.50, 10.6.0.51, 10.6.1.0/24", 1.05, 5.0, 4.9, .85, 13, RGBColor(190, 220, 230))
box(s, 6.85, 1.5, 5.75, 4.85, WHITE, ORANGE, True); text(s, "What the report gives the operator", 7.15, 1.85, 4.9, .35, 18, ORANGE, True)
bullet_list(s, ["Exact groups and IPs affected", "Original values preserved", "Unmapped or out-of-scope items", "Explicit pass/fail safety contract", "A clear apply / do-not-apply decision", "Rerun is a safe no-op once complete"], 7.2, 2.65, 4.8, 16, NAVY, .53)
footer(s, 5)

# 6
s = prs.slides.add_slide(prs.slide_layouts[6]); box(s, 0, 0, 13.333, 7.5, WHITE); title(s, "Workflow B — separate environment implementations", "Nonprod and production are independent live environments")
box(s, .8, 1.55, 5.55, 4.8, LIGHT, BLUE, True); text(s, "NONPROD — STANDALONE", 1.15, 1.95, 4.6, .4, 21, BLUE, True); text(s, "Single Local Manager", 1.15, 2.6, 3.5, .35, 17, NAVY, True); bullet_list(s, ["Used by the bank for live application testing", "Capture and review the remap report", "Apply groups-only, strict-additive remap", "Reruns detect no remaining additions", "Verify this environment independently"], 1.15, 3.35, 4.7, 15, MID, .58)
box(s, 6.95, 1.55, 5.55, 4.8, LIGHT, GREEN, True); text(s, "PRODUCTION — SEPARATE", 7.3, 1.95, 4.6, .4, 21, GREEN, True); text(s, "Global Manager + 3 Local Managers", 7.3, 2.6, 4.7, .35, 17, NAVY, True); bullet_list(s, ["Separate production environment; no promotion from nonprod", "Run the approved process against required GM domains", "Each Local Manager receives its local scope", "Verify each site and retain rollback baselines"], 7.3, 3.35, 4.7, 16, MID, .68)
text(s, "INDEPENDENT CHANGE WINDOWS", 4.35, 6.65, 4.65, .25, 12, ORANGE, True, PP_ALIGN.CENTER)
footer(s, 6)

# 7
s = prs.slides.add_slide(prs.slide_layouts[6]); box(s, 0, 0, 13.333, 7.5, LIGHT); title(s, "Workflows A / C / D — target implementation", "Each workflow creates the right objects for its destination")
box(s, .8, 1.55, 3.55, 4.7, WHITE, BLUE, True); text(s, "A  Clone to AVS", 1.15, 1.95, 2.8, .4, 22, BLUE, True); bullet_list(s, ["Copy services, groups, policies, and rules", "Strip segments for the target LM", "Verify object parity and membership"], 1.15, 2.8, 2.8, 16, MID, .72)
box(s, 4.9, 1.55, 3.55, 4.7, WHITE, TEAL, True); text(s, "C  Siblings to AVS", 5.25, 1.95, 3.0, .4, 22, TEAL, True); bullet_list(s, ["Create IP-only sibling groups", "Move effective IP membership into siblings", "Amend rule references and verify"], 5.25, 2.8, 2.8, 16, MID, .72)
box(s, 9.0, 1.55, 3.55, 4.7, WHITE, GREEN, True); text(s, "D  Siblings to on-prem nonprod", 9.35, 1.95, 3.1, .55, 20, GREEN, True); bullet_list(s, ["Create CSV-mapped sibling groups", "Keep source IPs on originals by default", "Use separate, reversible change windows"], 9.35, 2.95, 2.8, 16, MID, .72)
footer(s, 7)

# 8
s = prs.slides.add_slide(prs.slide_layouts[6]); box(s, 0, 0, 13.333, 7.5, NAVY); text(s, "The operating rule", .7, .65, 11.5, .6, 31, WHITE, True)
text(s, "No write without a report.\nNo production change without verification.", .75, 1.75, 11.8, 1.3, 30, WHITE, True)
for i, (head, desc, color) in enumerate([("Review", "Dry-run report", BLUE), ("Approve", "Change window", ORANGE), ("Apply", "Explicit write", TEAL), ("Prove", "Live verification", GREEN)]):
    x = .8 + i*3.05; box(s, x, 4.15, 2.55, 1.35, color, color, True); text(s, head, x+.15, 4.42, 2.2, .35, 18, WHITE, True, PP_ALIGN.CENTER); text(s, desc, x+.15, 4.9, 2.2, .25, 13, WHITE, False, PP_ALIGN.CENTER)
text(s, "Source: project runbooks and generated delivery reports in docs/nsx and nsx_avs_runs.", .75, 6.75, 11.6, .3, 11, RGBColor(190, 205, 220))
footer(s, 8)

prs.save(OUT)
print(OUT)
