import warnings
warnings.filterwarnings("ignore")

import os
import json
from typing import List
from fastapi import FastAPI, UploadFile, File, WebSocket, WebSocketDisconnect, Body
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict
from supabase import create_client, Client

from main import run_pipeline
from report_generator import ReportGenerator
from io import BytesIO
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

# ==========================================
# Supabase Setup
# ==========================================
# Credentials are read from environment variables, with the values below
# used as a fallback for local development only. In production, set
# SUPABASE_URL and SUPABASE_KEY in your deployment environment (or a
# .env file loaded via python-dotenv) rather than committing real keys
# to source control — this file's fallback key should be rotated in the
# Supabase dashboard if it has ever been shared or committed to a repo.
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://oqtffnfnqwgpxoxfpipf.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9xdGZmbmZucXdncHhveGZwaXBmIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODg4NzQ3MzMsImV4cCI6MjEwNDQ1MDczM30.s1FWKWj8q4mC8r3D640Y8Zp8pb9NTSj-wSTUBamPIlc")

if not SUPABASE_KEY:
    raise RuntimeError(
        "SUPABASE_KEY is not set. Export it as an environment variable "
        "before starting the server."
    )

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

app = FastAPI(title="Cyber Shield API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    # The dashboard is commonly opened directly as a local HTML file (Origin: null)
    # or served by a local dev server. Credentials are not used by this API.
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# 1. Models for C++ Engine Payloads
# ==========================================
class SuspiciousEvent(BaseModel):
    # Keep the original engine contract while allowing newer telemetry fields
    # (severity, risk_score, cipher_suite, packet/session counters, etc.) to
    # pass through to the WebSocket stream. Unknown fields are not written to
    # the legacy alerts table unless explicitly whitelisted below.
    model_config = ConfigDict(extra="allow")
    engine_source: str
    scan_mode: str
    timestamp: str
    protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    reason: str
    starttls_command_seen: bool
    server_acked_starttls: bool
    tls_handshake_seen: bool
    tls_client_hello_version: str
    severity: str | None = None
    risk_score: float | None = None
    cipher_suite: str | None = None
    packets_per_sec: float | None = None
    sessions_screened: int | None = None

# ==========================================
# 2. WebSocket Manager for Live Dashboard
# ==========================================
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        stale = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                stale.append(connection)
        for connection in stale:
            self.disconnect(connection)

manager = ConnectionManager()

# ==========================================
# 3. API Routes
# ==========================================

@app.get("/")
def root():
    return {"status": "online", "message": "Cyber Shield Backend is running", "health": "/api/health"}

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "cyber-shield-backend"}

@app.get("/api/history")
async def get_history():
    """Fetch recent alerts and threat logs from Supabase tables."""
    try:
        alerts_res = supabase.table("alerts").select("*").order("id", desc=True).limit(50).execute()
        threats_res = supabase.table("threat_logs").select("*").order("id", desc=True).limit(50).execute()
        return {
            "alerts": alerts_res.data,
            "threat_logs": threats_res.data,
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/analytics")
async def get_analytics():
    """Return backend-derived telemetry for charts without generating mock data."""
    try:
        alerts_res = supabase.table("alerts").select("*").order("id", desc=True).limit(500).execute()
        threats_res = supabase.table("threat_logs").select("*").order("id", desc=True).limit(200).execute()
        return {"alerts": alerts_res.data, "threat_logs": threats_res.data}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.post("/api/events")
async def receive_live_event(event: SuspiciousEvent):
    """Endpoint for the local C++ engine (localengine.cpp) to post alerts."""
    event_dict = event.model_dump() if hasattr(event, "model_dump") else event.dict()

    # The existing alerts table is intentionally kept compatible with the
    # deployed schema. New telemetry is still streamed live even if the legacy
    # table has no matching column yet.
    db_fields = {
        "engine_source", "scan_mode", "timestamp", "protocol", "src_ip",
        "src_port", "dst_ip", "dst_port", "reason",
        "starttls_command_seen", "server_acked_starttls",
        "tls_handshake_seen", "tls_client_hello_version", "severity"
    }
    db_event = {k: v for k, v in event_dict.items() if k in db_fields and v is not None}
    try:
        supabase.table("alerts").insert(db_event).execute()
    except Exception as e:
        print(f"Supabase Event Insert Error: {e}")

    await manager.broadcast({
        "type": "live_alert",
        "data": event_dict,
    })

    return {"status": "success", "message": "Event received and logged"}

def _derive_pcap_security_fields(report_data: dict) -> dict:
    """Normalize PCAP score/verdict fields for the dashboard and exports."""
    summary = report_data.get("summary") if isinstance(report_data.get("summary"), dict) else {}
    candidates = [
        summary.get("highest_risk_score"), summary.get("risk_score"),
        report_data.get("highest_risk_score"), report_data.get("risk_score")
    ]
    scores = []

    def walk(v):
        if isinstance(v, dict):
            for k, x in v.items():
                if str(k).lower() in {"risk_score", "risk", "riskScore"}:
                    try:
                        n = float(x)
                        if 0 <= n <= 100:
                            scores.append(n)
                    except (TypeError, ValueError):
                        pass
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    walk(report_data)
    valid = [float(x) for x in candidates if isinstance(x, (int, float)) and 0 <= x <= 100]
    valid += scores
    risk = max(valid) if valid else 0.0
    findings = report_data.get("findings") or report_data.get("verdicts") or report_data.get("anomalies") or []
    finding_count = len(findings) if isinstance(findings, list) else 0
    explicit = str(summary.get("verdict") or report_data.get("verdict") or "").strip().lower()
    if explicit and any(x in explicit for x in ("safe", "normal", "clean", "benign", "pass", "ok")) and not any(x in explicit for x in ("unsafe", "threat", "risk")):
        verdict = "SAFE"
    elif explicit and any(x in explicit for x in ("critical", "high", "unsafe", "malicious", "threat", "danger")):
        verdict = "UNSAFE"
    elif risk >= 60:
        verdict = "UNSAFE"
    elif risk >= 30 or finding_count:
        verdict = "REVIEW"
    else:
        verdict = "SAFE"
    report_data["security_assessment"] = {
        "risk_score": round(risk, 2),
        "safety_score": round(100 - risk, 2),
        "verdict": verdict,
        "verdict_text": (
            "SAFE — no critical security risk was reported by the configured forensic checks."
            if verdict == "SAFE" else
            "REVIEW — findings or risk indicators require analyst review."
            if verdict == "REVIEW" else
            "UNSAFE — significant security risk indicators were reported."
        )
    }
    return report_data


def _pdf_findings(report_data: dict) -> list:
    """Extract actual finding records for a human-readable PDF."""
    results, seen = [], set()
    def add(item):
        if not isinstance(item, dict):
            return
        reason = next((item.get(k) for k in ("reason","finding","title","name","message","description","issue") if item.get(k) is not None), None)
        severity = next((item.get(k) for k in ("severity","level","status") if item.get(k) is not None), None)
        score = next((item.get(k) for k in ("risk_score","risk","riskScore") if item.get(k) is not None), None)
        protocol = next((item.get(k) for k in ("protocol","proto") if item.get(k) is not None), None)
        src = next((item.get(k) for k in ("src_ip","source_ip","src","source") if item.get(k) is not None), None)
        dst = next((item.get(k) for k in ("dst_ip","destination_ip","dst","destination") if item.get(k) is not None), None)
        if reason is None and severity is None:
            return
        key = json.dumps([reason,score,severity,protocol,src,dst], default=str, ensure_ascii=False)
        if key in seen:
            return
        seen.add(key)
        results.append({"reason":reason or "Finding reported","severity":severity or "Unspecified","score":score,"protocol":protocol or "—","src":src or "—","dst":dst or "—"})
    for key in ("findings","verdicts","anomalies","alerts","threats","results"):
        value=report_data.get(key)
        if isinstance(value,list):
            for item in value: add(item)
        elif isinstance(value,dict):
            for item in value.values():
                if isinstance(item,list):
                    for sub in item: add(sub)
                else: add(item)
    return results[:100]


@app.post("/api/pcap/report/pdf")
async def download_pcap_pdf(report: dict = Body(...)):
    """Generate a real PDF containing only the selected PCAP report."""
    try:
        report_data = _derive_pcap_security_fields(dict(report or {}))
        assessment = report_data.get("security_assessment", {})
        summary = report_data.get("summary", {}) if isinstance(report_data.get("summary"),dict) else {}
        findings = _pdf_findings(report_data)
        source = os.path.basename(str(report_data.get("pcap_source") or report_data.get("filename") or "capture.pcap"))
        risk, safety = assessment.get("risk_score"), assessment.get("safety_score")
        verdict = str(assessment.get("verdict") or "NOT ASSESSED")
        verdict_text = str(assessment.get("verdict_text") or "The backend did not return enough evidence to issue a safety verdict.")

        buf=BytesIO()
        doc=SimpleDocTemplate(buf,pagesize=A4,rightMargin=15*mm,leftMargin=15*mm,topMargin=15*mm,bottomMargin=15*mm,title=f"Cryptoscope PCAP Report - {source}",author="Cryptoscope")
        styles=getSampleStyleSheet()
        brand=ParagraphStyle("Brand",parent=styles["Normal"],fontName="Helvetica-Bold",fontSize=10,textColor=colors.HexColor("#168C8A"),spaceAfter=8)
        title=ParagraphStyle("ReportTitle",parent=styles["Title"],fontName="Helvetica-Bold",fontSize=21,leading=25,textColor=colors.HexColor("#10233F"),spaceAfter=5)
        body=ParagraphStyle("Body",parent=styles["BodyText"],fontSize=9,leading=13,textColor=colors.HexColor("#344256"))
        small=ParagraphStyle("Small",parent=body,fontSize=8,leading=11,textColor=colors.HexColor("#708096"))
        h2=ParagraphStyle("H2",parent=styles["Heading2"],fontName="Helvetica-Bold",fontSize=12.5,leading=16,textColor=colors.HexColor("#172334"),spaceBefore=12,spaceAfter=8)
        mono=ParagraphStyle("Mono",parent=body,fontName="Courier",fontSize=7,leading=9,textColor=colors.HexColor("#3F4E61"))
        story=[Paragraph("CRYPTOSCOPE",brand),Paragraph("PCAP Forensic Report",title),Paragraph(xml_escape(source),small),Spacer(1,8)]
        vcolor={"SAFE":"#1D9B6C","REVIEW":"#B87500","UNSAFE":"#C93D57"}.get(verdict,"#66778B")
        vt=Table([[Paragraph("SECURITY VERDICT",small),Paragraph("RISK SCORE",small),Paragraph("SAFETY SCORE",small)],
                  [Paragraph(f"<b><font color='{vcolor}'>{xml_escape(verdict)}</font></b>",body),Paragraph(xml_escape("Not scored" if risk is None else f"{risk}/100"),body),Paragraph(xml_escape("Not available" if safety is None else f"{safety}/100"),body)]],colWidths=[70*mm,55*mm,55*mm])
        vt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#F3F7FB")),("BOX",(0,0),(-1,-1),.6,colors.HexColor("#DCE5EE")),("INNERGRID",(0,0),(-1,-1),.35,colors.HexColor("#E4EBF2")),("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),9),("RIGHTPADDING",(0,0),(-1,-1),9),("TOPPADDING",(0,0),(-1,-1),8),("BOTTOMPADDING",(0,0),(-1,-1),8)]))
        story += [vt,Spacer(1,8),Paragraph(xml_escape(verdict_text),body),Paragraph("Capture overview",h2)]
        overview=[["Capture file",source],["Streams analyzed",summary.get("total_streams_analyzed",report_data.get("analyzed_streams","—"))],["Anomalous streams",summary.get("anomalous_streams",summary.get("flagged_count","—"))],["Highest risk score",risk if risk is not None else "Not scored"],["Findings returned",len(findings)]]
        ot=Table([[Paragraph(f"<b>{xml_escape(str(k))}</b>",body),Paragraph(xml_escape(str(v)),body)] for k,v in overview],colWidths=[60*mm,120*mm])
        ot.setStyle(TableStyle([("BOX",(0,0),(-1,-1),.5,colors.HexColor("#DCE5EE")),("INNERGRID",(0,0),(-1,-1),.3,colors.HexColor("#E7EDF3")),("BACKGROUND",(0,0),(0,-1),colors.HexColor("#F7F9FC")),("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),7),("RIGHTPADDING",(0,0),(-1,-1),7),("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6)]))
        story.append(ot)
        story.append(Paragraph("Detected findings",h2))
        if findings:
            data=[[Paragraph("Finding",small),Paragraph("Severity",small),Paragraph("Risk",small),Paragraph("Protocol",small),Paragraph("Source",small),Paragraph("Destination",small)]]
            for f in findings:
                data.append([Paragraph(xml_escape(str(f["reason"])),body),Paragraph(xml_escape(str(f["severity"])),body),Paragraph(xml_escape("Not scored" if f["score"] is None else f'{f["score"]}/100'),body),Paragraph(xml_escape(str(f["protocol"])),body),Paragraph(xml_escape(str(f["src"])),mono),Paragraph(xml_escape(str(f["dst"])),mono)])
            ft=Table(data,colWidths=[62*mm,22*mm,20*mm,20*mm,28*mm,28*mm],repeatRows=1)
            ft.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#F3F7FB")),("BOX",(0,0),(-1,-1),.5,colors.HexColor("#DCE5EE")),("INNERGRID",(0,0),(-1,-1),.3,colors.HexColor("#E5EBF2")),("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),5),("RIGHTPADDING",(0,0),(-1,-1),5),("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6)]))
            story.append(ft)
        else: story.append(Paragraph("No individual findings were returned by the forensic backend.",body))
        story += [Paragraph("Assessment note",h2),Paragraph(xml_escape(verdict_text),body),Spacer(1,5),Paragraph("This PDF contains only the selected PCAP report. Dashboard history and other captures are not included.",small),Paragraph("Backend summary",h2)]
        rows=[]
        for k,v in summary.items():
            if isinstance(v,(dict,list)): v=json.dumps(v,ensure_ascii=False)
            rows.append([Paragraph(xml_escape(str(k).replace("_"," ").title()),body),Paragraph(xml_escape(str(v)),body)])
        if rows:
            st=Table(rows,colWidths=[60*mm,120*mm]); st.setStyle(TableStyle([("BOX",(0,0),(-1,-1),.5,colors.HexColor("#DCE5EE")),("INNERGRID",(0,0),(-1,-1),.3,colors.HexColor("#E7EDF3")),("BACKGROUND",(0,0),(0,-1),colors.HexColor("#F7F9FC")),("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),7),("RIGHTPADDING",(0,0),(-1,-1),7),("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5)])); story.append(st)
        story += [Spacer(1,12),Paragraph("Generated by Cryptoscope • PCAP forensic analysis",small)]
        doc.build(story); buf.seek(0)
        base=os.path.splitext(source)[0] or "pcap-report"
        return StreamingResponse(buf,media_type="application/pdf",headers={"Content-Disposition":f'attachment; filename="{base}_report.pdf"'})
    except Exception as e:
        return JSONResponse(status_code=500,content={"error":f"PDF generation failed: {e}"})


@app.post("/api/upload")
async def upload_pcap(file: UploadFile = File(...)):
    """Endpoint for the dashboard to upload .pcap files for the forensics pipeline."""
    if not file.filename or not file.filename.endswith((".pcap", ".pcapng")):
        return JSONResponse(status_code=400, content={"error": "Only .pcap or .pcapng files allowed."})

    safe_name = os.path.basename(file.filename)
    temp_pcap_path = os.path.join(os.getenv("PCAP_TMP_DIR", "."), f"temp_{safe_name}")

    try:
        with open(temp_pcap_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)

        # Run 9-stage forensics pipeline
        verdicts = run_pipeline(temp_pcap_path)
        report_str = ReportGenerator.to_json(verdicts, pcap_source=file.filename)
        report_data = json.loads(report_str)
        report_data = _derive_pcap_security_fields(report_data)
        summary_data = dict(report_data.get("summary", {}))
        summary_data["security_assessment"] = report_data.get("security_assessment", {})

        try:
            supabase.table("threat_logs").insert({
                "filename": file.filename,
                "summary": summary_data,
            }).execute()
        except Exception as e:
            print(f"Supabase PCAP Log Insert Error: {e}")

        await manager.broadcast({
            "type": "pcap_job_complete",
            "filename": file.filename,
            "summary": summary_data,
            "security_assessment": report_data.get("security_assessment", {}),
        })

        return report_data

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
    finally:
        if os.path.exists(temp_pcap_path):
            os.remove(temp_pcap_path)

@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ==========================================
# 4. Entry Point
# ==========================================
if __name__ == "__main__":
    import uvicorn
    print("Starting Cyber Shield FastAPI Backend on http://127.0.0.1:8000 ...")
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)