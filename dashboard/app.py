# ============================================================
# dashboard/app.py — Flask Web Dashboard
# HOW TO RUN: python dashboard/app.py
# Open: http://localhost:5000
# ============================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, jsonify
from crypto_utils import encrypt_text, decrypt_text

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    data     = request.get_json()
    text     = data.get("text", "").strip()
    password = data.get("password", "").strip()

    if not text:
        return jsonify({"error": "Input text is empty"}), 400
    if not password:
        return jsonify({"error": "Password is empty"}), 400
    if len(password) < 4:
        return jsonify({"error": "Password must be at least 4 characters"}), 400

    try:
        ciphertext = encrypt_text(text, password)
        return jsonify({
            "success":    True,
            "ciphertext": ciphertext,
            "algorithm":  "AES-256-GCM",
            "kdf":        "PBKDF2-HMAC-SHA256 (120,000 iterations)",
            "message":    "Text encrypted successfully"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    data       = request.get_json()
    ciphertext = data.get("ciphertext", "").strip()
    password   = data.get("password", "").strip()

    if not ciphertext:
        return jsonify({"error": "Ciphertext is empty"}), 400
    if not password:
        return jsonify({"error": "Password is empty"}), 400

    try:
        plaintext = decrypt_text(ciphertext, password)
        return jsonify({
            "success":   True,
            "plaintext": plaintext,
            "message":   "Text decrypted successfully"
        })
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": "Decryption failed: " + str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)