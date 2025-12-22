# 📧 Phishing Email Investigation (SOC Project)

## 🧠 Overview
This project demonstrates a **SOC analyst–style phishing email investigation**.  
The goal is to analyze a suspicious email, identify malicious indicators, and determine the threat level.

---

## 🎯 Objectives
- Analyze phishing email headers
- Identify spoofing and sender anomalies
- Extract and analyze URLs and attachments
- Collect Indicators of Compromise (IOCs)
- Provide a final threat verdict

---

## 🛠 Tools Used
- [Email Header Analyzer](https://toolbox.googleapps.com/apps/emailheader/)
- [VirusTotal](https://www.virustotal.com/)
- [URLScan.io](https://urlscan.io/)
- [WHOIS Lookup](https://whois.domaintools.com/)
- [CyberChef](https://gchq.github.io/CyberChef/)


---

## 🔍 Investigation Steps
🔍 Investigation Steps
1. **Email header analysis** – Identify the sender IP, SPF, DKIM, and DMARC records
2. **Body content inspection** – Look for social engineering cues
3. **URL reputation analysis** – Check if embedded links are malicious
4. **Attachment behavior analysis** – Scan for malware hashes or sandbox execution
5. **IOC extraction** – Collect all Indicators of Compromise
6. **Final verdict** – Determine if the email is phishing or legitimate

---

## 🚨 Indicators of Compromise (IOCs)
- Malicious URLs
- Suspicious sender IPs
- Malicious domains
- Hash values (if attachments present)

---

## ✅ Final Verdict
**Confirmed Phishing Email**  
The email demonstrates multiple phishing characteristics including spoofed sender details, malicious URLs, and social engineering techniques.

---

## 📚 Learning Outcome
- Hands-on phishing investigation experience
- Improved threat analysis skills
- SOC-ready incident response workflow

---

## ⚠️ Disclaimer
All email samples and data used in this project are **sanitized and for educational purposes only**.

