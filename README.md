# 22_SAHI
# Website Audit Pro (API-enabled)

A colorful, judge-friendly dashboard that audits any website for **Performance, Security, SEO, and Accessibility** — with **Google PageSpeed Insights** and **Wappalyzer** integrations.

## ✨ Features
- Live status, load time, content size
- SSL validity & expiry
- Security headers & cookie flags
- SEO (title, description, keywords, robots.txt, sitemap.xml)
- Accessibility (images without alt)
- Broken links (limited sample)
- **Google PageSpeed Insights** (real performance score) — optional API
- **Wappalyzer** tech detection — optional API
- Overall score (0–100) with charts
- One-click **PDF report**

## 🚀 Quick Start
```bash
pip install -r requirements.txt
python app.py
# open http://127.0.0.1:5000
```

## 🔑 Add API Keys (optional but recommended)
Create/modify `config.json`:
```json
{
  "GOOGLE_API_KEY": "YOUR_API_KEY_HERE",
  "WAPPALYZER_API_KEY": "YOUR_API_KEY_HERE"
}
```

- Google PageSpeed API: https://developers.google.com/speed/docs/insights/v5/get-started
- Wappalyzer API: https://www.wappalyzer.com/api/

## 🧰 Project Structure
```
website_audit_tool_pro/
├── app.py
├── config.json            # put your API keys here
├── requirements.txt
├── README.md
├── templates/
│   ├── layout.html
│   ├── index.html
│   └── result.html
└── static/
    └── style.css
```

## 📝 Notes
- PDF export is generated with **reportlab** (no external binaries needed).
- Broken link checker is capped to 20 links to keep the app responsive.
- PageSpeed and Wappalyzer gracefully **fallback** when keys are missing.
