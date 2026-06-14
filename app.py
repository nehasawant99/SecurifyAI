from ai_engine import analyze_security_log
import json
from flask import Flask, render_template, request, jsonify, Response
import sqlite3
import datetime

app = Flask(__name__)

# Route for the main page
@app.route('/')
def index():
    return render_template('index.html')

# Route to handle threat analysis
@app.route('/analyze', methods=['POST'])
def analyze_threat():

    try:
        data = request.get_json()

        log_data = data.get("logData", "")

        if not log_data:
            return jsonify({
                "error": "No log data provided"
            }), 400

        ai_response = analyze_security_log(log_data)

        ai_response = (
            ai_response
            .replace("```json", "")
            .replace("```", "")
            .strip()
        )

        result = json.loads(ai_response)

        timestamp = datetime.datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        conn = sqlite3.connect('securifyai.db')
        cursor = conn.cursor()

        cursor.execute(
            '''
            INSERT INTO analysis_results
            (
                log_data,
                severity,
                threat_type,
                root_cause,
                remediation,
                patch,
                confidence_score,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                log_data,
                result.get("severity", "Unknown"),
                result.get("threat_type", "Unknown"),
                result.get("root_cause", ""),
                result.get("remediation", ""),
                result.get("patch", ""),
                int(result.get("confidence_score", 90)),
                timestamp
            )
        )

        conn.commit()
        conn.close()

        return jsonify(result)

    except Exception as e:
         print("\nERROR:")
         print(e)


    return jsonify({
            "error": str(e)
        }), 500

# Route to simulate attacks and generate log data
@app.route('/simulate/<attack_type>', methods=['GET'])
def simulate_attack(attack_type):
    attack_type = attack_type.lower().strip()  # normalize

    simulations = {
        "sql": "SELECT * FROM users WHERE id = '1' OR '1'='1';",
        "xss": "<script>alert('XSS');</script>",
        "path": "../../etc/passwd",
        "clean": "GET /index.html HTTP/1.1"
    }

    log_data = simulations.get(attack_type, "Unknown attack type")

    # Save into DB for persistence
    with sqlite3.connect('securifyai.db') as conn:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO simulated_logs (attack_type, log_data) VALUES (?, ?)', (attack_type, log_data))
        conn.commit()

    return jsonify({"logData": log_data})

# Route to view scan history
@app.route('/scan-history', methods=['GET'])
def scan_history():
    try:
        with sqlite3.connect('securifyai.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT timestamp, threat_type, severity FROM analysis_results ORDER BY id DESC')
            rows = cursor.fetchall()
        history = [{"timestamp": row[0], "threat_type": row[1], "severity": row[2]} for row in rows]
        return jsonify(history)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route to generate an executive security report
@app.route('/generate-report', methods=['GET'])
def generate_report():
    conn = sqlite3.connect('securifyai.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM analysis_results ORDER BY id DESC LIMIT 1')
    row = cursor.fetchone()
    conn.close()

    if not row:
        return "No analysis results found.", 404

    # Extract data
    report_data = {
        "log_data": row[1],
        "severity": row[2],
        "threat_type": row[3],
        "root_cause": row[4],
        "remediation": row[5],
        "patch": row[6],
        "confidence_score": row[7],
        "timestamp": row[8]
    }

    # Generate HTML report
    report_html = f"""
    <html>
    <head>
      <title>Executive Security Report</title>
    </head>
    <body>
      <h1>Executive Security Report</h1>
      <p><strong>Timestamp:</strong> {report_data['timestamp']}</p>
      <p><strong>Threat Type:</strong> {report_data['threat_type']}</p>
      <p><strong>Severity:</strong> {report_data['severity']}</p>
      <p><strong>Root Cause:</strong> {report_data['root_cause']}</p>
      <p><strong>Remediation:</strong> {report_data['remediation']}</p>
      <p><strong>Patch:</strong> {report_data['patch'] or "No patch required"}</p>
      <p><strong>Confidence Score:</strong> {report_data['confidence_score']}%</p>
    </body>
    </html>
    """
    # Return the HTML report
    return Response(report_html, mimetype='text/html')

    

# Initialize the database
def init_db():
    conn = sqlite3.connect('securifyai.db')
    cursor = conn.cursor()

    # Create scan history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            severity TEXT NOT NULL
        )
    ''')

    # Create simulated logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS simulated_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_type TEXT NOT NULL,
            log_data TEXT NOT NULL
        )
    ''')

    # Create analysis results table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_data TEXT NOT NULL,
            severity TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            root_cause TEXT NOT NULL,
            remediation TEXT NOT NULL,
            patch TEXT,
            confidence_score INTEGER NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()

# Call the function to initialize the database
init_db()

if __name__ == '__main__':
    app.run(debug=True)