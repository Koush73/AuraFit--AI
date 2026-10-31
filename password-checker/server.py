"""
server.py – Flask REST API for SecureGuard Password Strength Analyzer
Run: python server.py
API base: http://localhost:5000
"""

import csv
import io
import os

from flask import Flask, jsonify, request, send_file, send_from_directory
from flask_cors import CORS

import analyzer
import database

# ──────────────────────────────────────────
# App setup
# ──────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Do NOT set static_url_path="" — it intercepts /api routes.
# Instead we serve static files via explicit routes below.
app = Flask(__name__, static_folder=None)
CORS(app, resources={r"/api/*": {"origins": "*"}})


# ──────────────────────────────────────────
# Serve frontend static files explicitly
# (avoids route conflict with /api/* paths)
# ──────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/style.css")
def serve_css():
    return send_from_directory(BASE_DIR, "style.css")

@app.route("/app.js")
def serve_js():
    return send_from_directory(BASE_DIR, "app.js")


# ──────────────────────────────────────────
# Helper
# ──────────────────────────────────────────

def err(msg: str, code: int = 400):
    return jsonify({"error": msg}), code


def _resolve_account(username: str):
    """Return the account dict or raise 404 JSON response."""
    acc = database.account_by_username(username)
    return acc


# ──────────────────────────────────────────
# API Routes
# ──────────────────────────────────────────

# POST /api/account
# Body: { "username": "alice" }
# Creates or fetches an account.
@app.route("/api/account", methods=["POST"])
def create_account():
    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    if not username:
        return err("username is required")
    if len(username) > 80:
        return err("username too long (max 80 chars)")
    account = database.get_or_create_account(username)
    return jsonify({"account": account}), 200


# POST /api/analyze
# Body: { "password": "P@ssw0rd!" }
# Returns strength analysis (does NOT save to DB).
@app.route("/api/analyze", methods=["POST"])
def analyze_password():
    data     = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not isinstance(password, str):
        return err("password must be a string")
    result = analyzer.analyze(password)
    # Don't return plain password in analyze-only response
    result_safe = {k: v for k, v in result.items() if k != "password"}
    return jsonify({"analysis": result_safe}), 200


# POST /api/history
# Body: { "username": "alice", "password": "P@ssw0rd!" }
# Analyzes AND saves to DB.
@app.route("/api/history", methods=["POST"])
def save_to_history():
    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password", "")

    if not username:
        return err("username is required")
    if not password:
        return err("password is required")

    account = database.get_or_create_account(username)
    analysis = analyzer.analyze(password)
    entry = database.save_password(account["id"], analysis)

    return jsonify({
        "message": "Saved successfully",
        "entry":   entry,
        "analysis": {k: v for k, v in analysis.items() if k != "password"},
    }), 201


# GET /api/history/<username>
# Returns all saved password history for the given account.
@app.route("/api/history/<username>", methods=["GET"])
def get_history(username: str):
    account = _resolve_account(username)
    if not account:
        return jsonify({"history": [], "account": None}), 200
    history = database.get_history(account["id"])
    return jsonify({"history": history, "account": account}), 200


# DELETE /api/history/<id>
# Body: { "username": "alice" }
# Deletes a specific history entry (validates it belongs to the user).
@app.route("/api/history/<int:entry_id>", methods=["DELETE"])
def delete_history(entry_id: int):
    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    if not username:
        return err("username is required")

    account = _resolve_account(username)
    if not account:
        return err("Account not found", 404)

    deleted = database.delete_entry(entry_id, account["id"])
    if not deleted:
        return err("Entry not found or not authorised", 404)
    return jsonify({"message": "Deleted"}), 200


# GET /api/stats/<username>
# Returns aggregate stats for the account.
@app.route("/api/stats/<username>", methods=["GET"])
def get_stats(username: str):
    account = _resolve_account(username)
    if not account:
        return jsonify({"stats": {"total": 0, "avg_score": None, "best_score": None, "weak_count": 0}}), 200
    stats = database.get_stats(account["id"])
    return jsonify({"stats": stats}), 200


# GET /api/export/<username>
# Streams a CSV file of the account's full password history.
@app.route("/api/export/<username>", methods=["GET"])
def export_csv(username: str):
    account = _resolve_account(username)
    if not account:
        return err("Account not found", 404)

    history = database.get_history(account["id"])

    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "#", "Timestamp", "Account", "Password", "Score", "Grade",
        "Length", "Has Uppercase", "Has Lowercase", "Has Number",
        "Has Special", "No Repeating Chars", "Not Common Password", "Entropy",
    ])

    # Rows
    for i, entry in enumerate(reversed(history), start=1):
        writer.writerow([
            i,
            entry["created_at"],
            username,
            entry["password"],
            entry["score"],
            entry["grade"],
            entry["length"],
            "Yes" if entry["has_upper"]   else "No",
            "Yes" if entry["has_lower"]   else "No",
            "Yes" if entry["has_number"]  else "No",
            "Yes" if entry["has_special"] else "No",
            "Yes" if entry["no_repeat"]   else "No",
            "No"  if entry["is_common"]   else "Yes",
            entry["entropy"],
        ])

    output.seek(0)
    safe_name = "".join(c for c in username if c.isalnum() or c in "-_")
    filename  = f"secureguard_{safe_name}.csv"

    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8-sig")),
        mimetype="text/csv",
        as_attachment=True,
        download_name=filename,
    )


# ──────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  SecureGuard – Password Strength Analyzer")
    print("  Backend: Flask + SQLite")
    print("  Open:    http://localhost:5000")
    print("=" * 55)
    database.init_db()
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)

