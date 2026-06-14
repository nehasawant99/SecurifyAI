import google.generativeai as genai
from dotenv import load_dotenv
import os

load_dotenv()

genai.configure(
    api_key=os.getenv("GEMINI_API_KEY")
)

model = genai.GenerativeModel("gemini-2.5-flash")

def analyze_security_log(log_data):

    prompt = f"""
You are SecurifyAI.

Analyze the security log.

Return ONLY valid JSON.

{{
  "severity":"",
  "threat_type":"",
  "root_cause":"",
  "remediation":"",
  "patch":"",
  "confidence_score":""
}}

Threat Types:
- SQL Injection
- XSS
- Path Traversal
- Brute Force
- Clean Traffic

Severity:
- Low
- Medium
- High
- Critical

Log:
{log_data}
"""

    response = model.generate_content(prompt)

    return response.text