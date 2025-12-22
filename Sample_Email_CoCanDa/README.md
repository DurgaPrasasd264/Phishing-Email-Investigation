# CoCanDa Phishing Email Investigation

## 📧 Case Overview
A suspicious email related to the abduction incidents on planet CoCanDa was received by a CoCanDa Army Major on Earth. The email demanded money and contained an encoded attachment. This investigation analyzes the email to determine whether it is malicious.

---

## 🔐 Sample Information
- File Name: cocanda_email.zip  
- File Type: Password-protected phishing email sample  
- Password: `btlo`

⚠️ The file is password-protected to prevent accidental execution.

---

## 🎯 Objective
- Identify phishing indicators in the email
- Analyze headers, content, and attachments
- Extract Indicators of Compromise (IOCs)
- Provide a final threat verdict

---

## 🛠 Tools Used
- Email Header Analyzer
- VirusTotal
- CyberChef
- File Signature Database
- Virtual Machine (Isolated Environment)

---

## 🔍 Investigation Steps

### 1️⃣ Email Extraction
- The email sample ZIP file was extracted in an isolated virtual machine.
- Inside the archive, a `.eml` email file was identified for analysis.

![Alt Text (Description of the image)](images/image1.png)
![Alt Text](https://github.com/DurgaPrasasd264/Phishing-Email-Investigation/images/image1.png?raw=true)
---

### 2️⃣ Sender & Reply-To Analysis
- The sender email domain differed from the reply-to email address.
- This mismatch indicates **email spoofing**, a common phishing technique.

---

### 3️⃣ Email Content Analysis
- The email body contained a **ransom demand**, requesting money.
- The message used fear and urgency, indicating **social engineering**.

---

### 4️⃣ Header Analysis
- Email headers were analyzed using an Email Header Analyzer.
- Findings:
  - SPF: ❌ Failed
  - DKIM: ❌ Failed
  - DMARC: ❌ Failed

📌 This confirms the email was **not authorized** by the sending domain.

---

### 5️⃣ IP Reputation Check
- The sender IP address was checked on VirusTotal.
- No prior malicious activity was reported.
- However, clean IPs do not guarantee legitimacy.

---

### 6️⃣ Attachment Analysis (Base64 Decoding)
- The email contained Base64-encoded data claiming to be a PDF.
- The Base64 content was decoded using CyberChef.
- File signature analysis of the first 8 bytes revealed:
  - The file was **not a PDF**
  - The file was actually a **ZIP archive**

📌 This indicates **file type spoofing**.

---

### 7️⃣ ZIP Extraction
- The ZIP file was extracted safely.
- Three folders were discovered inside the archive.

---

### 8️⃣ File Review
- The first folders contained image files (`.png`).
- The final folder contained a location and instructions demanding money delivery.

---

## 🚨 Indicators of Compromise (IOCs)

| Type | Value |
|-----|------|
| Sender Email | Spoofed domain |
| Reply-To Email | Different from sender |
| Authentication | SPF/DKIM/DMARC failed |
| Attachment Type | ZIP (disguised as PDF) |
| Encoding | Base64 |
| Attack Technique | Social Engineering |

---

## ✅ Final Verdict
**Confirmed Phishing Email**

The email demonstrates multiple phishing indicators including spoofed sender details, authentication failures, disguised attachments, and ransom-based social engineering.

---

## 📚 Learning Outcome
- Practical phishing email investigation
- Header and authentication analysis
- Base64 decoding and file signature identification
- Safe handling of malicious email samples
- SOC-style incident response workflow

---

## ⚠️ Disclaimer
This investigation is for educational purposes only. All analysis was performed in an isolated environment.

