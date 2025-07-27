# 🛡️ Phishing Email Analysis Report (Cybersecurity Internship Task 2)

## 🎯 Objective
Analyze a sample phishing email to identify suspicious characteristics, using **Kali Linux tools** and free online resources. The aim is to detect red flags in the sender, links, tone, and headers.

---

## 🔧 Tools Used
- **Kali Linux**
- `whois`, `dig` command (terminal-based lookup)
- [VirusTotal](https://www.virustotal.com)
- [MxToolbox Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)
- [Google Admin Toolbox](https://toolbox.googleapps.com)

---

## 📨 Sample Phishing Email (Simulated)
```
From: support@paypai.com
Subject: Urgent - Your Account is Suspended
Body:
Your PayPal account has been flagged. Click the link below to verify your account:
http://malicious-paypai.com/verify
Failure to act will result in permanent suspension.
```

---

## 🧪 Step-by-Step Analysis Using Kali Linux

### ✅ Step 1: Whois Lookup (Check Domain Legitimacy)
```bash
whois malicious-paypai.com
```
📸 Screenshot: `screenshots/whois_lookup.png`
- Shows domain is **recently created**, **unrelated to PayPal**.

---

### ✅ Step 2: DNS Records Lookup (Using `dig`)
```bash
dig malicious-paypai.com
```
📸 Screenshot: `screenshots/dns_records.png`
- Minimal DNS records, low reputation, possibly malicious host.

---

### ✅ Step 3: Scan URL on VirusTotal
- Go to: https://virustotal.com
- Paste URL: `http://malicious-paypai.com/verify`
📸 Screenshot: `screenshots/virustotal_report.png`
- Flagged as **phishing/malware by multiple engines**.

---

### ✅ Step 4: Analyze Email Header with MxToolbox
- Visit: https://mxtoolbox.com/EmailHeaders.aspx
- Paste raw email headers.
📸 Screenshot: `screenshots/header_analysis.png`
- SPF/DKIM/DMARC failed. Origin IP doesn't match PayPal.

---

### ✅ Step 5: Identify Phishing Red Flags
| Feature | Detected |
|--------|----------|
| Spoofed sender | ✅ `support@paypai.com` (typo) |
| Threatening language | ✅ "Account suspended" |
| Suspicious URL | ✅ `http://malicious-paypai.com` |
| Generic greeting | ✅ "Dear User" |
| No personalization | ✅ |
| No digital signature | ✅ |

📸 Screenshot: `screenshots/email_body.png`

---

## 🛡️ Conclusion
This simulated email is a **textbook phishing attempt**:
- Spoofed domain
- Urgency language
- Malicious URL
- Failed email header checks

It aims to **steal credentials** by imitating PayPal. Using Kali tools like `whois`, `dig`, and online analyzers like VirusTotal and MxToolbox, we confirmed the email is **highly dangerous**.

---

## 📂 Repository Structure
```
phishing-email-analysis/
├── README.md
├── screenshots/
│   ├── whois_lookup.png
│   ├── dns_records.png
│   ├── virustotal_report.png
│   ├── header_analysis.png
│   └── email_body.png
```

> 💡 Remember: Never trust emails that rush you into action or ask you to click on unverified links. Always inspect the source and validate domains carefully.

---

✅ Task Completed by: **Nitin sanap**
