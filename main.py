from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
import requests
import sqlite3
from fpdf import FPDF
import uuid
import os

app = FastAPI()

# --- WEKA SECRET KEY YAKO HAPA (Chukua Flutterwave Dashboard -> Settings -> API Keys) ---
FLW_SECRET_KEY = "FLWSECK_TEST-344eef063af108e4df242d522fc4423a-X" 

# 1. Database Setup
def init_db():
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans 
        (id TEXT PRIMARY KEY, url TEXT, score TEXT, status TEXT)
    """)
    conn.commit()
    conn.close()

init_db()

# 2. PDF Generator Logic
def generate_pdf(scan_id, url, score, fixes):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="SENTINEL AI - FORENSIC REPORT", ln=True, align='C')
    pdf.ln(10)
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Target Domain: {url}", ln=True)
    pdf.cell(200, 10, txt=f"Security Score: {score}", ln=True)
    pdf.ln(10)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Vulnerabilities Found:", ln=True)
    pdf.set_font("Arial", size=10)
    for fix in fixes:
        pdf.multi_cell(0, 10, txt=f"- {fix}")
    
    os.makedirs("reports", exist_ok=True)
    path = f"reports/report_{scan_id}.pdf"
    pdf.output(path)

# 3. AI Auditor Logic
def ai_auditor(headers):
    score = 100
    tips = []
    if not headers.get("X-XSS-Protection"):
        score -= 30
        tips.append("XSS Protection is disabled. Sessions can be hijacked.")
    if "Strict-Transport-Security" not in headers:
        score -= 20
        tips.append("HSTS is missing. Site is vulnerable to SSL stripping.")
    
    color = "text-emerald-400" if score > 80 else ("text-yellow-400" if score > 50 else "text-red-500")
    return {"score": f"{score}/100", "verdict": "VULNERABLE" if score < 80 else "SECURE", "color": color, "fixes": tips}

# --- ROUTES ---

@app.get("/")
async def home():
    return FileResponse("templates/index.html")

@app.get("/scan")
def start_scan(url: str):
    try:
        if not url.startswith("http"): url = "https://" + url
        res = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=7)
        analysis = ai_auditor(res.headers)
        scan_id = str(uuid.uuid4())[:8]
        
        conn = sqlite3.connect("sentinel.db")
        conn.execute("INSERT INTO scans VALUES (?, ?, ?, ?)", (scan_id, url, analysis["score"], "Pending"))
        conn.commit()
        conn.close()
        
        generate_pdf(scan_id, url, analysis["score"], analysis["fixes"])
        return {"id": scan_id, "target": url, "report": analysis}
    except:
        return {"error": "Target unreachable"}

@app.post("/pay/{scan_id}")
async def pay(scan_id: str, url: str):
    if "YOUR-KEY-HERE" in FLW_SECRET_KEY or not FLW_SECRET_KEY.startswith("FLWSECK"):
        return {"status": "error", "message": "Invalid Flutterwave Secret Key!"}

    payload = {
        "tx_ref": scan_id,
        "amount": "19", 
        "currency": "USD",
        "redirect_url": "http://127.0.0",
        "payment_options": "card, mpesa, paypal",
        "customer": {"email": "customer@sentinel.ai", "name": "Sentinel User"},
        "customizations": {"title": "Sentinel AI Report", "description": f"Security Audit for {url}"}
    }
    headers = {"Authorization": f"Bearer {FLW_SECRET_KEY}", "Content-Type": "application/json"}
    
    try:
        response = requests.post("https://flutterwave.com", json=payload, headers=headers, timeout=15)
        
        # HAKIKI KAMA JIBU NI JSON
        if response.status_code == 200:
            return response.json()
        else:
            return {"status": "error", "message": f"Flutterwave Error {response.status_code}: {response.text[:100]}"}
    except Exception as e:
        return {"status": "error", "message": f"Network Error: {str(e)}"}

@app.get("/verify-payment")
async def verify(status: str, tx_ref: str, transaction_id: str):
    if status == "successful":
        headers = {"Authorization": f"Bearer {FLW_SECRET_KEY}"}
        verify_res = requests.get(f"https://flutterwave.com{transaction_id}/verify", headers=headers).json()
        
        if verify_res.get("status") == "success":
            conn = sqlite3.connect("sentinel.db")
            conn.execute("UPDATE scans SET status = 'Paid' WHERE id = ?", (tx_ref,))
            conn.commit()
            conn.close()
            return RedirectResponse(url=f"/?paid={tx_ref}")
            
    return RedirectResponse(url="/?error=failed")

@app.get("/download/{scan_id}")
def download(scan_id: str):
    conn = sqlite3.connect("sentinel.db")
    row = conn.execute("SELECT status FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if row and row[0] == "Paid":
        return FileResponse(f"reports/report_{scan_id}.pdf", media_type='application/pdf')
    return {"error": "Payment Required"}
