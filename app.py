import os
from datetime import datetime, timedelta, timezone

import psycopg2
from flask import Flask, jsonify, request


app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL")
MASTER_KEY = os.environ.get("MASTER_KEY")


def get_db_connection():
    """Create a PostgreSQL connection."""
    try:
        return psycopg2.connect(DATABASE_URL)
    except Exception as e:
        print(f"Database connection failed: {e}")
        return None


def as_utc(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso_z(dt):
    return as_utc(dt).isoformat().replace("+00:00", "Z")


def get_hwid_candidates(data):
    old_hwid = data.get("old_hwid")
    old_hwid_candidates = data.get("old_hwid_candidates") or []
    if not isinstance(old_hwid_candidates, list):
        old_hwid_candidates = []
    return [value for value in [old_hwid, *old_hwid_candidates] if value]


# ===================================================================
# K7 / 91 script license API
# ===================================================================


@app.route("/verify", methods=["POST"])
def verify_key():
    if request.headers.get("X-API-Key") != MASTER_KEY:
        return jsonify({"status": "failure", "message": "Invalid API key"}), 401

    data = request.get_json(silent=True) or {}
    key = data.get("key")
    hwid = data.get("hwid")
    script_id = data.get("script_id")

    if not all([key, hwid, script_id]):
        return jsonify({"status": "failure", "message": "Missing key, hwid or script_id"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"status": "failure", "message": "Database connection error"}), 500

    cur = conn.cursor()
    try:
        cur.execute(
            'SELECT hwid, "expireAt", "script_type", "duration_days" '
            'FROM "LicenseKeys" WHERE key = %s',
            (key,),
        )
        result = cur.fetchone()

        if not result:
            return jsonify({"status": "failure", "message": "Invalid license key"}), 200

        stored_hwid, expires_at, stored_script_type, duration_days = result
        expires_at_utc = as_utc(expires_at)
        now = datetime.now(timezone.utc)

        if stored_script_type != script_id:
            return jsonify({"status": "failure", "message": "License type mismatch"}), 200

        if stored_hwid is None:
            print(f"Binding license {key} to hwid {hwid}")

            # First activation for duration-based keys: start counting only now.
            if duration_days and duration_days > 0 and expires_at is None:
                new_expire_at = now + timedelta(days=duration_days)
                cur.execute(
                    'UPDATE "LicenseKeys" SET hwid = %s, "expireAt" = %s WHERE key = %s',
                    (hwid, new_expire_at, key),
                )
                conn.commit()
                message = {
                    "status": "success",
                    "message": f"Activated for {duration_days} days",
                    "expires_at": iso_z(new_expire_at),
                }

            # Already activated then unbound: bind a new device but keep the old expiry.
            elif expires_at_utc and expires_at_utc > now:
                cur.execute(
                    'UPDATE "LicenseKeys" SET hwid = %s WHERE key = %s',
                    (hwid, key),
                )
                conn.commit()
                print(f"Re-bound license {key} to {hwid}; expiry preserved: {expires_at}")
                message = {
                    "status": "success",
                    "message": "Bound successfully",
                    "expires_at": iso_z(expires_at),
                }
            else:
                message = {"status": "failure", "message": "License is invalid or expired"}

        else:
            legacy_hwids = set(get_hwid_candidates(data))
            is_migrating_hwid = stored_hwid != hwid and stored_hwid in legacy_hwids

            if stored_hwid != hwid and not is_migrating_hwid:
                message = {"status": "failure", "message": "HWID mismatch"}
            elif expires_at_utc is None:
                message = {"status": "failure", "message": "License state error: missing expiry"}
            elif expires_at_utc < now:
                message = {"status": "failure", "message": "License expired"}
            else:
                if is_migrating_hwid:
                    cur.execute(
                        'UPDATE "LicenseKeys" SET hwid = %s WHERE key = %s AND hwid = %s',
                        (hwid, key, stored_hwid),
                    )
                    conn.commit()
                    print(f"Migrated license {key} from legacy hwid to new hwid")
                message = {
                    "status": "success",
                    "message": "Verified successfully",
                    "expires_at": iso_z(expires_at),
                }

        return jsonify(message), 200

    except Exception as e:
        conn.rollback()
        return jsonify({"status": "failure", "message": str(e)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/unbind", methods=["POST"])
def unbind_key():
    if request.headers.get("X-API-Key") != MASTER_KEY:
        return jsonify({"status": "failure", "message": "Invalid API key"}), 401

    data = request.get_json(silent=True) or {}
    key = data.get("key")
    hwid = data.get("hwid")

    if not key or not hwid:
        return jsonify({"status": "failure", "message": "Missing parameters"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"status": "failure", "message": "Database connection error"}), 500

    cur = conn.cursor()
    try:
        allowed_hwids = [hwid, *get_hwid_candidates(data)]
        cur.execute(
            'UPDATE "LicenseKeys" SET hwid = NULL WHERE key = %s AND hwid = ANY(%s)',
            (key, allowed_hwids),
        )
        conn.commit()
        message = (
            {"status": "success", "message": "Unbound successfully"}
            if cur.rowcount > 0
            else {"status": "failure", "message": "Unbind failed or not found"}
        )
        return jsonify(message), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"status": "failure", "message": str(e)}), 500
    finally:
        cur.close()
        conn.close()


# ===================================================================
# Transaction log API
# ===================================================================


@app.route("/log_transaction", methods=["POST"])
def log_transaction():
    if request.headers.get("X-API-Key") != MASTER_KEY:
        return jsonify({"status": "failure", "message": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    license_key = data.get("license_key")
    client_account = data.get("client_account")
    trans_type = data.get("type")
    amount = data.get("amount")

    if not license_key:
        return jsonify({"status": "failure", "message": "Missing license key"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"status": "failure", "message": "Database error"}), 500

    cur = conn.cursor()
    try:
        cur.execute(
            'INSERT INTO "TransactionLogs" '
            "(license_key, client_account, transaction_type, amount) "
            "VALUES (%s, %s, %s, %s)",
            (license_key, client_account, trans_type, amount),
        )
        conn.commit()
        return jsonify({"status": "success", "message": "Log saved successfully"}), 200
    except Exception as e:
        conn.rollback()
        print(f"Failed to save transaction log: {e}")
        return jsonify({"status": "failure", "message": str(e)}), 500
    finally:
        cur.close()
        conn.close()


# ===================================================================
# Legacy recharge client API
# ===================================================================


@app.route("/api/create_user", methods=["POST"])
def create_user():
    data = request.get_json(silent=True) or {}
    license_key = data.get("license_key")
    password = data.get("password")

    if not license_key or not password:
        return jsonify({"status": "failure", "message": "license_key and password are required"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"status": "failure", "message": "Database error"}), 500

    cur = conn.cursor()
    try:
        cur.execute(
            'INSERT INTO "user" (license_key, password) VALUES (%s, %s)',
            (license_key, password),
        )
        conn.commit()
        return jsonify({"status": "success", "message": "Created successfully"}), 201
    except psycopg2.IntegrityError:
        conn.rollback()
        return jsonify({"status": "failure", "message": "License key already exists"}), 409
    except Exception as e:
        conn.rollback()
        return jsonify({"status": "failure", "message": str(e)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    license_key = data.get("license_key")
    password = data.get("password")

    if not license_key or not password:
        return jsonify({"status": "failure", "message": "license_key and password are required"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"status": "failure", "message": "Database error"}), 500

    cur = conn.cursor()
    try:
        cur.execute('SELECT password FROM "user" WHERE license_key = %s', (license_key,))
        user = cur.fetchone()
        if user and user[0] == password:
            return jsonify(
                {
                    "status": "success",
                    "message": "Login successful",
                    "user": {"license_key": license_key},
                }
            ), 200
        return jsonify({"status": "failure", "message": "Authentication failed"}), 401
    finally:
        cur.close()
        conn.close()


@app.route("/api/log_recharge", methods=["POST"])
def log_recharge_entry():
    data = request.get_json(silent=True) or {}
    license_key = data.get("license_key")
    game_account = data.get("game_account")

    if not license_key or not game_account:
        return jsonify({"status": "failure", "message": "Missing license_key or game_account"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"status": "failure", "message": "Database error"}), 500

    cur = conn.cursor()
    try:
        cur.execute('SELECT id FROM "user" WHERE license_key = %s', (license_key,))
        user_record = cur.fetchone()
        if not user_record:
            return jsonify({"status": "failure", "message": "User license key not found"}), 404

        user_id = user_record[0]
        cur.execute(
            'INSERT INTO "game_account_log" (user_id, account_name) VALUES (%s, %s)',
            (user_id, game_account),
        )
        conn.commit()
        return jsonify({"status": "success", "message": "Recharge log saved"}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"status": "failure", "message": str(e)}), 500
    finally:
        cur.close()
        conn.close()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
