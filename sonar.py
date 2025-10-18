import os
import requests
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import argparse
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER


def fetch_metrics(sonar_host, project_key, auth, headers):
    metric_keys = ",".join([
        "bugs", "vulnerabilities", "code_smells", "coverage",
        "duplicated_lines_density", "complexity", "reliability_rating",
        "security_rating", "sqale_rating", "functions", "classes"
    ])
    url = f"{sonar_host}/api/measures/component?component={project_key}&metricKeys={metric_keys}"
    return requests.get(url, auth=auth, headers=headers).json().get("component", {}).get("measures", [])


def fetch_project_info(sonar_host, project_key, auth, headers):
    url = f"{sonar_host}/api/projects/search?projects={project_key}"
    return requests.get(url, auth=auth, headers=headers).json().get("components", [{}])[0]


def fetch_quality_gate_status(sonar_host, project_key, auth, headers):
    url = f"{sonar_host}/api/qualitygates/project_status?projectKey={project_key}"
    return requests.get(url, auth=auth, headers=headers).json().get("projectStatus", {})


def fetch_quality_gate_conditions(sonar_host, project_key, auth, headers):
    url = f"{sonar_host}/api/qualitygates/get_by_project?project={project_key}"
    resp = requests.get(url, auth=auth, headers=headers).json()
    return resp.get("conditions", [])


def fetch_issues(sonar_host, project_key, auth, headers):
    page_size = 300
    base_url = f"{sonar_host}/api/issues/search"
    query_params = f"componentKeys={project_key}&ps={page_size}&statuses=OPEN,REOPENED,CONFIRMED"

    initial_url = f"{base_url}?{query_params}&p=1"
    initial = requests.get(initial_url, auth=auth, headers=headers).json()
    total = initial.get("total", 0)
    total_pages = (total + page_size - 1) // page_size

    def get_page(page):
        url = f"{base_url}?{query_params}&p={page}"
        return requests.get(url, auth=auth, headers=headers).json().get("issues", [])

    with ThreadPoolExecutor() as executor:
        all_pages = list(executor.map(get_page, range(1, total_pages + 1)))

    return [item for sublist in all_pages for item in sublist]


def generate_charts(metrics, issues, charts_dir):
    os.makedirs(charts_dir, exist_ok=True)
    metric_dict = {
        m["metric"]: float(m["value"]) if m["value"].replace('.', '', 1).isdigit() else m["value"]
        for m in metrics
    }

    plt.bar(['bugs', 'vulnerabilities', 'code_smells'],
            [metric_dict.get(k, 0) for k in ['bugs', 'vulnerabilities', 'code_smells']],
            color='skyblue')
    plt.title('Code Quality Issues')
    plt.ylabel('Count')
    plt.tight_layout()
    plt.savefig(f"{charts_dir}/code_quality_issues.png")
    plt.close()

    issue_types = pd.Series([i['type'] for i in issues]).value_counts()
    issue_types.plot.pie(
        autopct='%1.1f%%',
        figsize=(6, 6),
        title='Issue Types Distribution',
        colors=['#ff9999', '#66b3ff', '#99ff99', '#ffcc99']
    )
    plt.ylabel("")
    plt.tight_layout()
    plt.savefig(f"{charts_dir}/issue_types.png")
    plt.close()


def add_page_number(canvas, doc):
    page_num = canvas.getPageNumber()
    text = f"Page {page_num}"
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(A4[0] - inch / 2, 0.75 * inch, text)


#  Mapping for renamed display labels
DISPLAY_NAME_MAP = {
    "reliability_rating": "Reliability",
    "security_rating": "Security",
    "sqale_rating": "Maintainability",
    "duplicated_lines_density": "Duplication"
}


def generate_pdf(metrics, project, gate, issues, grades_conditions, charts_dir, output_pdf):
    generate_charts(metrics, issues, charts_dir)

    doc = SimpleDocTemplate(
        output_pdf, pagesize=A4,
        rightMargin=inch / 2, leftMargin=inch / 2,
        topMargin=inch, bottomMargin=inch
    )
    elements = []
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(name='Justify', alignment=TA_LEFT, leading=14))
    styles.add(ParagraphStyle(name='TableHeader', fontSize=9, leading=11, alignment=TA_CENTER, fontName='Helvetica-Bold', textColor=colors.white))
    styles.add(ParagraphStyle(name='TableCell', fontSize=8, leading=10, alignment=TA_LEFT))
    styles.add(ParagraphStyle(name='TitleCenter', parent=styles['Title'], alignment=TA_CENTER))
    styles.add(ParagraphStyle(name='ChartCaption', fontSize=9, alignment=TA_CENTER, spaceAfter=12))
    styles.add(ParagraphStyle(name='GradeCell', fontSize=16, alignment=TA_CENTER, fontName='Helvetica-Bold'))

    elements.append(Paragraph(f"SonarQube Report - {project.get('key')}", styles['TitleCenter']))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Spacer(1, 24))

    raw_status = gate.get("status", "UNKNOWN")
    gate_color = colors.green if raw_status == "OK" else colors.red
    readable_status = "PASS" if raw_status == "OK" else "FAIL"

    gate_text = f"<b>Quality Gate Status:</b> <font color='{gate_color.hexval()}'>{readable_status}</font>"
    elements.append(Paragraph(gate_text, styles['Heading2']))
    elements.append(Spacer(1, 18))

    metric_map = {m['metric']: m['value'] for m in metrics}
    summary_metrics_keys = ["bugs", "vulnerabilities", "code_smells", "coverage", "duplicated_lines_density"]
    summary_data = [["Metric", "Value"]]
    for key in summary_metrics_keys:
        val = metric_map.get(key, "-")
        if key in ["coverage", "duplicated_lines_density"]:
            val = f"{val}%" if val != "-" else val
        label = DISPLAY_NAME_MAP.get(key, key.replace('_', ' ').title())
        summary_data.append([label, val])

    summary_table = Table(summary_data, colWidths=[doc.width * 0.6, doc.width * 0.4])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#34495e")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 24))

    elements.append(Paragraph("<b>Overall Grade:</b>", styles['Heading2']))
    metrics_data = [["Metric", "Value"]]

    # Mapping numeric rating to grade letter for these three keys
    def format_metric_value(key, value):        
        rating_map = {
            1: "A",
            2: "B",
            3: "C",
            4: "D",
            5: "E"
        }

        if key in ["reliability_rating", "security_rating", "sqale_rating"]:
            try:
                num_value = int(float(value))
                return rating_map.get(num_value, str(value))
            except Exception:
                return str(value)

        if key in ["coverage", "duplicated_lines_density"]:
            return f"{value}%" if value != "-" else value

        if isinstance(value, float):
            return f"{value:.2f}"

        return str(value)

    bottom_keys = {"reliability_rating", "security_rating", "sqale_rating"}
    bottom_metrics = []
    top_metrics = []

    for m in metrics:
        if m['metric'] in bottom_keys:
            bottom_metrics.append(m)
        else:
            top_metrics.append(m)

    for m in top_metrics + bottom_metrics:
        key = DISPLAY_NAME_MAP.get(m['metric'], m['metric'].replace('_', ' ').title())
        val = format_metric_value(m['metric'], m['value'])
        metrics_data.append([key, val])

    metrics_table = Table(metrics_data, colWidths=[doc.width * 0.6, doc.width * 0.4])
    metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#34495e")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.lightgrey]),
        ('ALIGN', (1, 1), (1, -1), 'CENTER'),
    ]))
    elements.append(metrics_table)
    elements.append(Spacer(1, 24))

    elements.append(Paragraph("<b>Charts:</b>", styles['Heading2']))
    elements.append(Image(f"{charts_dir}/code_quality_issues.png", width=5 * inch, height=3 * inch))
    elements.append(Paragraph("Figure 1: Code Quality Issues Overview", styles['ChartCaption']))
    elements.append(Spacer(1, 12))
    elements.append(Image(f"{charts_dir}/issue_types.png", width=5 * inch, height=3 * inch))
    elements.append(Paragraph("Figure 2: Issue Types Distribution", styles['ChartCaption']))
    elements.append(PageBreak())

    elements.append(Paragraph(f"<b>Issues ({len(issues)}):</b>", styles['Heading2']))
    issue_data = [["Key", "Severity", "Type", "Message", "Component", "Line", "Status"]]
    for issue in issues:
        issue_data.append([
            Paragraph(issue.get('key', ''), styles['TableCell']),
            Paragraph(issue.get('severity', ''), styles['TableCell']),
            Paragraph(issue.get('type', ''), styles['TableCell']),
            Paragraph(issue.get('message', '').replace('<', '&lt;').replace('>', '&gt;'), styles['TableCell']),
            Paragraph(issue.get('component', ''), styles['TableCell']),
            Paragraph(str(issue.get('line', '-')), styles['TableCell']),
            Paragraph(issue.get('status', ''), styles['TableCell']),
        ])

    col_widths = [
        doc.width * 0.1,
        doc.width * 0.09,
        doc.width * 0.09,
        doc.width * 0.35,
        doc.width * 0.2,
        doc.width * 0.07,
        doc.width * 0.1
    ]

    table = Table(issue_data, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#2980b9")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.4, colors.grey),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.lightgrey]),
        ('ALIGN', (5, 1), (5, -1), 'CENTER'),
        ('ALIGN', (1, 1), (2, -1), 'CENTER'),
        ('ALIGN', (6, 1), (6, -1), 'CENTER'),
    ]))
    elements.append(table)

    doc.build(elements, onFirstPage=add_page_number, onLaterPages=add_page_number)
    print(f"PDF report saved to {output_pdf}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--project', required=True)
    parser.add_argument('--token', required=True)
    parser.add_argument('--output', default='sonarqube_report.pdf')
    parser.add_argument('--charts-dir', default='charts')
    args = parser.parse_args()

    auth = (args.token, "")
    headers = {"Accept": "application/json"}

    print("Fetching data from SonarQube...")
    with ThreadPoolExecutor() as executor:
        futures = {
            "metrics": executor.submit(fetch_metrics, args.host, args.project, auth, headers),
            "project": executor.submit(fetch_project_info, args.host, args.project, auth, headers),
            "gate": executor.submit(fetch_quality_gate_status, args.host, args.project, auth, headers),
            "issues": executor.submit(fetch_issues, args.host, args.project, auth, headers),
            "grades": executor.submit(fetch_quality_gate_conditions, args.host, args.project, auth, headers)
        }

        metrics = futures["metrics"].result()
        project = futures["project"].result()
        gate = futures["gate"].result()
        issues = futures["issues"].result()
        grades_conditions = futures["grades"].result()

    print("Generating PDF report...")
    generate_pdf(metrics, project, gate, issues, grades_conditions, args.charts_dir, args.output)
