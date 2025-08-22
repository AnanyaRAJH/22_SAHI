from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify
import requests
from bs4 import BeautifulSoup
import ssl, socket, validators, time, json, io, re
from urllib.parse import urlparse, urljoin
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm

app = Flask(__name__)

def load_config():
    try:
        with open("config.json", "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"GOOGLE_API_KEY": "", "WAPPALYZER_API_KEY": ""}

CFG = load_config()

def domain_from_url(u: str) -> str:
    try:
        p = urlparse(u)
        return p.hostname or u.replace("https://","").replace("http://","").split("/")[0]
    except Exception:
        return u

def check_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return True, cert.get("notAfter")
    except Exception:
        return False, None

def safe_get(url, **kwargs):
    try:
        return requests.get(url, timeout=kwargs.get("timeout", 10), allow_redirects=True, headers={"User-Agent":"Mozilla/5.0 WebsiteAuditTool"})
    except Exception as e:
        return None

def get_pagespeed(url):
    key = CFG.get("GOOGLE_API_KEY","")
    if not key:
        return {"available": False, "note": "No Google API key configured."}
    endpoint = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
    try:
        res = requests.get(endpoint, params={"url": url, "strategy":"mobile", "key": key}, timeout=20)
        if res.status_code != 200:
            return {"available": False, "note": f"PageSpeed error {res.status_code}"}
        data = res.json()
        lighthouse = data.get("lighthouseResult",{})
        categories = lighthouse.get("categories",{})
        perf = categories.get("performance",{}).get("score", None)
        fcp = lighthouse.get("audits",{}).get("first-contentful-paint",{}).get("displayValue")
        lcp = lighthouse.get("audits",{}).get("largest-contentful-paint",{}).get("displayValue")
        tbt = lighthouse.get("audits",{}).get("total-blocking-time",{}).get("displayValue")
        cls = lighthouse.get("audits",{}).get("cumulative-layout-shift",{}).get("displayValue")
        return {"available": True, "performance_score": int(round((perf or 0)*100)), "fcp": fcp, "lcp": lcp, "tbt": tbt, "cls": cls}
    except Exception as e:
        return {"available": False, "note": str(e)}

def get_wappalyzer(url):
    key = CFG.get("WAPPALYZER_API_KEY","")
    if not key:
        return {"available": False, "note": "No Wappalyzer API key configured."}
    try:
        res = requests.get(
            "https://api.wappalyzer.com/v2/lookup/",
            params={"urls": url},
            headers={"x-api-key": key, "Accept":"application/json"},
            timeout=15
        )
        if res.status_code != 200:
            return {"available": False, "note": f"Wappalyzer error {res.status_code}"}
        data = res.json()
        tech = []
        if isinstance(data, list) and data:
            for item in data[0].get("technologies", []):
                tech.append({"name": item.get("name"), "categories":[c.get("name") for c in item.get("categories",[])]})
        return {"available": True, "technologies": tech}
    except Exception as e:
        return {"available": False, "note": str(e)}

def broken_links(url, html, limit=20):
    soup = BeautifulSoup(html, "html.parser")
    base = url
    links = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith("#") or href.startswith("mailto:") or href.startswith("javascript:"):
            continue
        full = urljoin(base, href)
        links.append(full)
        if len(links) >= limit:
            break
    broken = []
    checked = 0
    for l in links:
        try:
            r = requests.head(l, timeout=6, allow_redirects=True)
            code = r.status_code
            if code >= 400:
                broken.append({"url": l, "status": code})
        except Exception:
            broken.append({"url": l, "status": "ERR"})
        checked += 1
    return {"checked": checked, "broken": broken}

def cookie_security(headers):
    cookies = headers.get("Set-Cookie","")
    flags = {"Secure": False, "HttpOnly": False, "SameSite": False}
    if not cookies:
        return {"cookies_set": False, "flags": flags}
    flags["Secure"] = "secure" in cookies.lower()
    flags["HttpOnly"] = "httponly" in cookies.lower()
    flags["SameSite"] = "samesite" in cookies.lower()
    return {"cookies_set": True, "flags": flags}

def compute_scores(report):
    perf = report.get("pagespeed",{})
    perf_score = perf.get("performance_score", None)
    if perf.get("available") and isinstance(perf_score, int):
        ps = perf_score
    else:
        try:
            lt = float(report["load_time_seconds"])
            if lt <= 1.5: ps = 90
            elif lt <= 3: ps = 75
            elif lt <= 5: ps = 60
            else: ps = 40
        except Exception:
            ps = 50
    need = ["Content-Security-Policy","Strict-Transport-Security","X-Frame-Options","X-Content-Type-Options","Referrer-Policy"]
    present = sum(1 for h in need if report.get("security_headers",{}).get(h) == "Present")
    ssl_bonus = 1 if report.get("ssl_valid") else 0
    cookie = report.get("cookie_security",{}).get("flags",{})
    cookie_bonus = sum(1 for v in cookie.values() if v)
    sec_score = int(round(((present + ssl_bonus + cookie_bonus) / (len(need) + 1 + 3)) * 100))
    seo_ok = 0
    for f in ["title","meta_description","meta_keywords","robots_txt","sitemap_xml"]:
        v = report.get(f)
        if isinstance(v, str):
            seo_ok += (v != "Missing" and v != "Not found")
        elif isinstance(v, dict):
            seo_ok += bool(v)
        else:
            seo_ok += 0
    seo_score = int(round((seo_ok/5)*100))
    acc = report.get("accessibility",{})
    total_imgs = acc.get("images_total",0) or 0
    without_alt = acc.get("images_missing_alt",0) or 0
    if total_imgs == 0:
        acc_score = 80
    else:
        acc_score = int(round((1 - (without_alt/total_imgs)) * 100))
    overall = int(round(0.30*ps + 0.30*sec_score + 0.25*seo_score + 0.15*acc_score))
    return {"performance": ps, "security": sec_score, "seo": seo_score, "accessibility": acc_score, "overall": overall}

def audit(url):
    report = {"url": url}
    if not validators.url(url):
        report["error"] = "Invalid URL"
        return report
    start = time.time()
    resp = safe_get(url, timeout=15)
    load_time = time.time() - start
    if not resp:
        report["status"] = "Website unreachable"
        return report
    report["http_status"] = resp.status_code
    report["status"] = f"Live (HTTP {resp.status_code})"
    report["load_time_seconds"] = round(load_time, 2)
    report["content_bytes"] = len(resp.content)
    d = domain_from_url(url)
    ssl_ok, expiry = check_ssl(d)
    report["ssl_valid"] = ssl_ok
    report["ssl_expiry"] = expiry or "Unknown"
    soup = BeautifulSoup(resp.text, "html.parser")
    title = soup.title.string.strip() if soup.title and soup.title.string else None
    desc = soup.find("meta", attrs={"name":"description"})
    keywords = soup.find("meta", attrs={"name":"keywords"})
    report["title"] = title if title else "Missing"
    report["meta_description"] = (desc.get("content").strip() if (desc and desc.get("content")) else "Missing")
    report["meta_keywords"] = (keywords.get("content").strip() if (keywords and keywords.get("content")) else "Missing")
    need = ["Content-Security-Policy","Strict-Transport-Security","X-Frame-Options","X-Content-Type-Options","Referrer-Policy"]
    sec_headers = {h: ("Present" if h in resp.headers else "Missing") for h in need}
    report["security_headers"] = sec_headers
    report["cookie_security"] = cookie_security(resp.headers)
    base = url.rstrip("/")
    robots = safe_get(base + "/robots.txt", timeout=6)
    report["robots_txt"] = f"Found ({robots.status_code})" if (robots and robots.status_code == 200) else "Not found"
    sitemap = safe_get(base + "/sitemap.xml", timeout=6)
    report["sitemap_xml"] = f"Found ({sitemap.status_code})" if (sitemap and sitemap.status_code == 200) else "Not found"
    imgs = soup.find_all("img")
    missing_alt = [i for i in imgs if not i.get("alt")]
    report["accessibility"] = {"images_total": len(imgs), "images_missing_alt": len(missing_alt)}
    report["broken_links"] = broken_links(url, resp.text, limit=20)
    report["pagespeed"] = get_pagespeed(url)
    report["wappalyzer"] = get_wappalyzer(url)
    report["scores"] = compute_scores(report)
    return report

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/audit", methods=["POST"])
def do_audit():
    url = request.form.get("url","").strip()
    results = audit(url)
    return render_template("result.html", r=results)

@app.route("/export/pdf", methods=["POST"])
def export_pdf():
    data = request.get_json(force=True)
    packet = io.BytesIO()
    c = canvas.Canvas(packet, pagesize=A4)
    width, height = A4
    y = height - 2*cm
    def line(text, step=14):
        nonlocal y
        c.drawString(2*cm, y, text)
        y -= step
    c.setTitle("Website Audit Report")
    c.setFont("Helvetica-Bold", 16)
    line("Website Audit Report", 22)
    c.setFont("Helvetica", 11)
    line(f"URL: {data.get('url','')}")
    sc = data.get("scores",{})
    line(f"Overall Score: {sc.get('overall','-')}/100")
    line(f"Performance: {sc.get('performance','-')}/100")
    line(f"Security: {sc.get('security','-')}/100")
    line(f"SEO: {sc.get('seo','-')}/100")
    line(f"Accessibility: {sc.get('accessibility','-')}/100")
    line("")
    line("Key Findings:", 16)
    line(f"- Status: {data.get('status','')}")
    line(f"- Load Time: {data.get('load_time_seconds','-')} s")
    line(f"- SSL Valid: {data.get('ssl_valid', False)} (Expiry: {data.get('ssl_expiry','Unknown')})")
    sec_present = ', '.join([k for k,v in data.get('security_headers',{}).items() if v=='Present']) or 'None'
    line(f"- Security Headers Present: {sec_present}")
    line(f"- Robots.txt: {data.get('robots_txt','')}  Sitemap.xml: {data.get('sitemap_xml','')}")
    acc = data.get('accessibility',{})
    line(f"- Images: {acc.get('images_total',0)} total, {acc.get('images_missing_alt',0)} missing alt")
    bl = data.get('broken_links',{})
    line(f"- Links checked: {bl.get('checked',0)}, Broken: {len(bl.get('broken',[]))}")
    w = data.get('wappalyzer',{})
    if w.get('available') and w.get('technologies'):
        techs = ', '.join(sorted(set([t.get('name') for t in w.get('technologies',[]) if t.get('name')])))
        line(f"- Detected Tech: {techs[:90]}")
    c.showPage()
    c.save()
    packet.seek(0)
    return send_file(packet, mimetype="application/pdf", as_attachment=True, download_name="website_audit_report.pdf")

if __name__ == "__main__":
    app.run(debug=True)
