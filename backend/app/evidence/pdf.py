"""Human-readable PDF report (the signed manifest remains authoritative)."""
from __future__ import annotations

import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from xml.sax.saxutils import escape


def render_pdf(c: dict, chain_check: dict, key_id: str, wording: str) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f"MALLYA evidence report {c['incident']['ref']}")
    ss = getSampleStyleSheet()
    h = ParagraphStyle("h", parent=ss["Heading2"], fontSize=12, spaceBefore=10, spaceAfter=4)
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=8.5, leading=11)
    mono = ParagraphStyle("m", parent=body, fontName="Courier", fontSize=7.5, leading=9.5)

    def P(t, s=body):
        return Paragraph(escape(str(t)), s)

    def table(rows, widths=None):
        t = Table([[P(x) for x in r] for r in rows], colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e7e9ee")),
                               ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#b9bdc7")),
                               ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        return t

    inc = c["incident"]
    el = [Paragraph(f"MALLYA evidence report — {escape(inc['ref'])}", ss["Title"]),
          P(inc["title"]), Spacer(1, 4), P(wording), Spacer(1, 6),
          table([["Field", "Value"], ["Final status", c["final_status"]], ["Severity / risk score", f"{inc['severity']} / {inc['risk_score']}"],
                 ["Detected (UTC)", inc["detected_at"]], ["Exposure started (UTC)", inc["exposure_started_at"]],
                 ["Verified fixed (UTC)", inc["verified_fixed_at"] or "—"],
                 ["Access verdict", (c["access_verdict"] or {}).get("verdict", "—")],
                 ["Evidence chain", f"{'INTACT' if chain_check['ok'] else 'BROKEN'} · {chain_check['events']} events"],
                 ["Signing key", key_id]], [45 * mm, 125 * mm])]
    el += [Paragraph("Access verdict", h), P((c["access_verdict"] or {}).get("summary", "—"))]
    el += [Paragraph("Root cause", h)] + [P(rc["statement"]) for rc in c["root_cause"]]
    br = c["blast_radius"] or {}
    el += [Paragraph("Blast radius", h), P(f"{br.get('record_count', 0):,} records; categories {', '.join(br.get('data_categories', {}))}; "
                                           f"consent: {br.get('consent')}")]
    if br.get("locations"):
        el.append(table([["Location", "Matches", "Role"]] + [[x["location"], str(x["matches"]), x["role"]] for x in br["locations"] if x["present"]],
                        [100 * mm, 20 * mm, 50 * mm]))
    el += [Paragraph("Remediation actions", h),
           table([["Action", "Type / target", "Approval", "Execution"]] +
                 [[a["code"], f"{a['type']} — {a['target']}", a["approval_status"], a["execution_status"]] for a in c["actions"]],
                 [18 * mm, 98 * mm, 27 * mm, 27 * mm])]
    if c["approvals"]:
        el.append(Spacer(1, 4))
        el.append(table([["Decision", "By", "At (UTC)", "Presenter auto-approve"]] +
                        [[p["decision"], f"{p['by']} ({p['role']})", p["at"], "yes" if p["presenter_auto_approve"] else "no"] for p in c["approvals"]],
                        [25 * mm, 65 * mm, 50 * mm, 30 * mm]))
    for r in c["verification_runs"]:
        el += [Paragraph(f"Verification {r['ref']}: {r['verdict']}", h)]
        if r["residual"]:
            el.append(P("Residual exposure: " + ", ".join(r["residual"])))
        el.append(table([["Request", "Result"]] + [[f"{q.get('method')} {q.get('path')} [{q.get('layer')}]",
                                                    f"{q.get('status')} {q.get('outcome')}{' (cache HIT)' if q.get('served_from_cache') else ''}"]
                                                   for q in r["requests"]], [120 * mm, 50 * mm]))
    el += [Paragraph("Unverified locations / limitations", h)] + [P(x) for x in c["limitations"]]
    el += [Paragraph("Compliance drafts", h)] + [P(f"{d['title']} — {d['stamp']}") for d in c["compliance_drafts"]]
    el += [Spacer(1, 8), P("A concept prototype built for Redacto. Sandbox data only.", mono)]
    doc.build(el)
    return buf.getvalue()
