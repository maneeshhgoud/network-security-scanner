from datetime import datetime

def generate_html_report(results):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ─── Risk Badge Color ─────────────────────────────────────────
    def badge(risk):
        colors = {
            "HIGH":   ("background:#FCEBEB;color:#A32D2D;border:0.5px solid #F09595;"),
            "MEDIUM": ("background:#FAEEDA;color:#854F0B;border:0.5px solid #EF9F27;"),
            "LOW":    ("background:#EAF3DE;color:#3B6D11;border:0.5px solid #97C459;"),
        }
        style = colors.get(risk, "background:#F1EFE8;color:#5F5E5A;")
        return f'<span style="padding:3px 10px;border-radius:20px;font-size:11px;font-weight:500;{style}">{risk}</span>'

    # ─── Summary Cards ────────────────────────────────────────────
    def summary_cards(open_ports):
        high   = sum(1 for p in open_ports if p["risk"] == "HIGH")
        medium = sum(1 for p in open_ports if p["risk"] == "MEDIUM")
        low    = sum(1 for p in open_ports if p["risk"] == "LOW")
        total  = len(open_ports)
        return f"""
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:1.5rem 0;">
            <div style="background:#FCEBEB;border-radius:10px;padding:1rem;text-align:center;">
                <div style="font-size:11px;color:#A32D2D;font-weight:500;margin-bottom:4px;">HIGH RISK</div>
                <div style="font-size:28px;font-weight:500;color:#A32D2D;">{high}</div>
            </div>
            <div style="background:#FAEEDA;border-radius:10px;padding:1rem;text-align:center;">
                <div style="font-size:11px;color:#854F0B;font-weight:500;margin-bottom:4px;">MEDIUM RISK</div>
                <div style="font-size:28px;font-weight:500;color:#854F0B;">{medium}</div>
            </div>
            <div style="background:#EAF3DE;border-radius:10px;padding:1rem;text-align:center;">
                <div style="font-size:11px;color:#3B6D11;font-weight:500;margin-bottom:4px;">LOW RISK</div>
                <div style="font-size:28px;font-weight:500;color:#3B6D11;">{low}</div>
            </div>
            <div style="background:#E6F1FB;border-radius:10px;padding:1rem;text-align:center;">
                <div style="font-size:11px;color:#185FA5;font-weight:500;margin-bottom:4px;">TOTAL OPEN</div>
                <div style="font-size:28px;font-weight:500;color:#185FA5;">{total}</div>
            </div>
        </div>"""

    # ─── Port Table ───────────────────────────────────────────────
    def port_table(open_ports):
        if not open_ports:
            return '<p style="color:#888;font-size:13px;">No open ports found.</p>'
        rows = ""
        for i, p in enumerate(open_ports):
            bg = "#ffffff" if i % 2 == 0 else "#f9f9f9"
            rows += f"""
            <tr style="background:{bg};">
                <td style="padding:10px 14px;font-family:monospace;font-weight:500;">{p['port']}</td>
                <td style="padding:10px 14px;">{p['service']}</td>
                <td style="padding:10px 14px;">{badge(p['risk'])}</td>
                <td style="padding:10px 14px;color:#666;font-size:12px;font-family:monospace;">{p['banner']}</td>
            </tr>"""
        return f"""
        <table style="width:100%;border-collapse:collapse;font-size:13px;margin-top:1rem;">
            <thead>
                <tr style="background:#f4f4f4;border-bottom:1px solid #e0e0e0;">
                    <th style="padding:10px 14px;text-align:left;font-weight:500;color:#444;">Port</th>
                    <th style="padding:10px 14px;text-align:left;font-weight:500;color:#444;">Service</th>
                    <th style="padding:10px 14px;text-align:left;font-weight:500;color:#444;">Risk</th>
                    <th style="padding:10px 14px;text-align:left;font-weight:500;color:#444;">Banner</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>"""

    # ─── Recommendations ──────────────────────────────────────────
    def recommendations(open_ports):
        recs = ""
        for p in open_ports:
            if p["risk"] == "HIGH":
                recs += f"""
                <div style="background:#FCEBEB;border-left:3px solid #E24B4A;border-radius:0 8px 8px 0;padding:10px 14px;margin-bottom:8px;">
                    <span style="font-size:12px;font-weight:500;color:#A32D2D;">Port {p['port']} — {p['service']}</span>
                    <p style="font-size:12px;color:#791F1F;margin:3px 0 0;">Immediate action required — restrict with firewall rules, disable if unused.</p>
                </div>"""
            elif p["risk"] == "MEDIUM":
                recs += f"""
                <div style="background:#FAEEDA;border-left:3px solid #EF9F27;border-radius:0 8px 8px 0;padding:10px 14px;margin-bottom:8px;">
                    <span style="font-size:12px;font-weight:500;color:#854F0B;">Port {p['port']} — {p['service']}</span>
                    <p style="font-size:12px;color:#633806;margin:3px 0 0;">Review whether this service is necessary. Apply access controls.</p>
                </div>"""
        if not recs:
            recs = '<p style="color:#3B6D11;font-size:13px;">No high or medium risk ports found.</p>'
        return recs

    # ─── Target Sections ─────────────────────────────────────────
    target_sections = ""
    for r in results:
        target_sections += f"""
        <div style="background:#fff;border:0.5px solid #e0e0e0;border-radius:12px;padding:1.5rem;margin-bottom:2rem;">
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:0.5rem;">
                <div style="background:#EEEDFE;color:#3C3489;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:500;">TARGET</div>
                <h2 style="font-size:18px;font-weight:500;margin:0;">{r['host']}</h2>
            </div>
            <p style="font-size:12px;color:#888;margin:0 0 0.5rem;">Scanned: {r['scan_time']} &nbsp;|&nbsp; OS: {r['os_guess']}</p>
            {summary_cards(r['open_ports'])}
            <h3 style="font-size:14px;font-weight:500;margin:1.5rem 0 0.25rem;">Open Ports</h3>
            {port_table(r['open_ports'])}
            <h3 style="font-size:14px;font-weight:500;margin:1.5rem 0 0.5rem;">Recommendations</h3>
            {recommendations(r['open_ports'])}
        </div>"""

    # ─── Full HTML Page ───────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network Security Scanner Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
          background: #f5f5f5; color: #222; line-height: 1.6; }}
  .page {{ max-width: 900px; margin: 0 auto; padding: 2rem 1rem; }}
  h1 {{ font-size: 22px; font-weight: 500; }}
  h2 {{ font-size: 18px; font-weight: 500; }}
  h3 {{ font-size: 15px; font-weight: 500; }}
</style>
</head>
<body>
<div class="page">
  <div style="margin-bottom:2rem;">
    <div style="background:#EEEDFE;color:#3C3489;display:inline-block;
                padding:4px 14px;border-radius:20px;font-size:11px;
                font-weight:500;margin-bottom:10px;">SECURITY REPORT</div>
    <h1>Network Security Scanner</h1>
    <p style="color:#888;font-size:13px;margin-top:4px;">
      Generated: {timestamp} &nbsp;|&nbsp; Targets scanned: {len(results)}
    </p>
    <div style="background:#FAEEDA;border-left:3px solid #EF9F27;
                border-radius:0 8px 8px 0;padding:10px 14px;margin-top:1rem;">
      <p style="font-size:12px;color:#633806;font-weight:500;">Ethical Disclaimer</p>
      <p style="font-size:12px;color:#854F0B;">
        This report is for authorized security testing only.
        Unauthorized scanning is illegal. Always obtain written permission.
      </p>
    </div>
  </div>
  {target_sections}
  <p style="text-align:center;font-size:12px;color:#aaa;margin-top:2rem;">
    Generated by Network Security Scanner — Maneesh Goud | CEH Certified
  </p>
</div>
</body>
</html>"""

    with open("report.html", "w") as f:
        f.write(html)
