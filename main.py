from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
import requests
import sqlite3
from fpdf import FPDF
import uuid
import os

app = FastAPI()

# --- CONFIGURATION ---
# Replace with your actual Flutterwave Secret Key
FLW_SECRET_KEY = "FLWSECK_TEST-acd0d1aad58c75eb98dc4e38a800d00d-X" 
# Replace with your actual Render URL
LIVE_URL = ""

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

# 2. PDF Generator Logic (Fixed for Linux/Render paths)
def generate_pdf(scan_id, url, score, fixes):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="SENTINEL AI - FORENSIC REPORT", ln=True, align='C')
    pdf.ln(10)
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Target: {url}", ln=True)
    pdf.cell(200, 10, txt=f"Security Score: {score}", ln=True)
    pdf.ln(10)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Vulnerabilities Found:", ln=True)
    pdf.set_font("Arial", size=10)
    for fix in fixes:
        pdf.multi_cell(0, 10, txt=f"- {fix}")
    
    if not os.path.exists("reports"):
        os.makedirs("reports")
    path = f"reports/report_{scan_id}.pdf"
    pdf.output(path)

# 3. AI Auditor Engine
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
    return {"score": f"{score}/100", "verdict": "Vulnerable" if score < 80 else "Secure", "color": color, "fixes": tips}

# --- ROUTES ---

@app.get("/", response_class=HTMLResponse)
async def home():
    # FIXED: This absolute path prevents 'Internal Server Error' on Render
    base_path = os.path.dirname(__file__)
    file_path = os.path.join(base_path, "templates", "index.html")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "Critical Error: templates/index.html not found. Check your folder structure."

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
        return {"error": "Unreachable"}

@app.post("/pay/{scan_id}")
async def pay(scan_id: str, url: str):
    if "YOUR-KEY-HERE" in FLW_SECRET_KEY:
        return {"status": "error", "message": "Missing Flutterwave Secret Key!"}

    payload = {
        "tx_ref": scan_id,
        "amount": "19", 
        "currency": "USD",
        "redirect_url": f"{LIVE_URL}/verify-payment", # UPDATED FOR LIVE SITE
        "payment_options": "card, mpesa, paypal",
        "customer": {"email": "customer@sentinel.ai", "name": "Sentinel User"},
        "customizations": {"title": "Sentinel AI Report", "description": f"Audit for {url}"}
    }
    headers = {"Authorization": f"Bearer {FLW_SECRET_KEY}", "Content-Type": "application/json"}
    
    try:
        response = requests.post("https://flutterwave.com", json=payload, headers=headers, timeout=15)
        if response.status_code == 200:
            return response.json()
        else:
            return {"status": "error", "message": f"Gateway Error: {response.text[:100]}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

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
    return {"error": "Payment required"}
