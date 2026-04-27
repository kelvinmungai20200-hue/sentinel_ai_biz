from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
import requests
import sqlite3
from fpdf import FPDF
import uuid
import os

app = FastAPI()

# --- CONFIGURATION ---
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "sk_test_YOUR_KEY_HERE") 
LIVE_URL = ""

# 1. Database Setup
def init_db():
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, url TEXT, score TEXT, status TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT, password TEXT)")
    conn.commit()
    conn.close()

init_db()

# 2. PDF Generator
def generate_pdf(scan_id, url, score, fixes):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="SENTINEL AI - FORENSIC SECURITY REPORT", ln=True, align='C')
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

# 3. AI Intelligence Engine
def ai_auditor(headers):
    score = 100
    tips = []
    if not headers.get("X-XSS-Protection"):
        score -= 30
        tips.append("XSS Protection is disabled. Sessions at risk.")
    if "Strict-Transport-Security" not in headers:
        score -= 20
        tips.append("HSTS is missing. Vulnerable to SSL Stripping.")
    
    color = "text-emerald-400" if score > 80 else ("text-yellow-400" if score > 50 else "text-red-500")
    return {"score": f"{score}/100", "verdict": "SECURE" if score > 80 else "VULNERABLE", "color": color, "fixes": tips}

# --- ROUTES ---

@app.get("/", response_class=HTMLResponse)
async def home():
    base_path = os.path.dirname(__file__)
    file_path = os.path.join(base_path, "templates", "index.html")
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()

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
        return {"error": "Target unreachable."}

# --- PAYSTACK PAYMENT ---
@app.post("/pay/{scan_id}")
async def pay(scan_id: str, url: str):
    amount = 19 * 100  # $19 in cents
    payload = {
        "reference": scan_id,
        "amount": amount,
        "currency": "USD",
        "email": "customer@sentinel.ai",
        "callback_url": f"{LIVE_URL}/verify-payment"
    }
    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}
    response = requests.post("https://paystack.co", json=payload, headers=headers)
    return response.json()

@app.get("/verify-payment")
async def verify(reference: str):
    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}
    res = requests.get(f"https://paystack.co{reference}", headers=headers).json()
    if res["status"] and res["data"]["status"] == "success":
        conn = sqlite3.connect("sentinel.db")
        conn.execute("UPDATE scans SET status = 'Paid' WHERE id = ?", (reference,))
        conn.commit()
        conn.close()
        return RedirectResponse(url=f"/?paid={reference}")
    return RedirectResponse(url="/?error=failed")

# --- AI CONSULTANT CHAT ---
@app.post("/ai-consultant")
async def ai_consultant(data: dict):
    msg = data.get("message", "").lower()
    if "hsts" in msg: reply = "HSTS ensures all connections are HTTPS. Add 'Strict-Transport-Security' header to fix it."
    elif "xss" in msg: reply = "XSS allows hackers to run scripts. Sanitize inputs and use Content-Security-Policy."
    else: reply = "I am Sentinel AI. I can explain XSS, HSTS, or your security score. How can I help?"
    return {"reply": reply}

@app.get("/download/{scan_id}")
def download(scan_id: str):
    conn = sqlite3.connect("sentinel.db")
    row = conn.execute("SELECT status FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if row and row[0] == "Paid":
        return FileResponse(f"reports/report_{scan_id}.pdf", media_type='application/pdf')
    return {"error": "Payment required"}
