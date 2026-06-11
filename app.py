import os
import json
from datetime import datetime, timedelta, timezone

import psycopg2
from flask import Flask, jsonify, request


app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL")
MASTER_KEY = os.environ.get("MASTER_KEY")
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY")
CLIENT_API_KEY = os.environ.get("CLIENT_API_KEY")
TENCENT_SECRET_ID = os.environ.get("TENCENT_SECRET_ID")
TENCENT_SECRET_KEY = os.environ.get("TENCENT_SECRET_KEY")
TENCENT_COS_REGION = os.environ.get("TENCENT_COS_REGION", "ap-shanghai")
TENCENT_COS_BUCKET = os.environ.get("TENCENT_COS_BUCKET")
TENCENT_COS_LATEST_KEY = os.environ.get("TENCENT_COS_LATEST_KEY", "updates/latest.json")
UPDATE_URL_EXPIRE_SECONDS = int(os.environ.get("UPDATE_URL_EXPIRE_SECONDS", "600"))
LEGACY_CLIENT_KEYS = {
    value.strip()
    for value in [
        MASTER_KEY,
        os.environ.get("LEGACY_CLIENT_KEY"),
        *os.environ.get("LEGACY_CLIENT_KEYS", "").split(","),
    ]
    if value and value.strip()
}

AUTH_ADMIN = "admin"
AUTH_CLIENT = "client"
AUTH_LEGACY = "legacy"


def get_cos_client():
    if not all([TENCENT_SECRET_ID, TENCENT_SECRET_KEY, TENCENT_COS_BUCKET]):
        raise RuntimeError("Tencent COS environment variables are incomplete")

    from qcloud_cos import CosConfig, CosS3Client

    cos_config = CosConfig(
        Region=TENCENT_COS_REGION,
        SecretId=TENCENT_SECRET_ID,
        SecretKey=TENCENT_SECRET_KEY,
        Scheme="https",
    )
    return CosS3Client(cos_config)


def read_update_manifest():
    client = get_cos_client()
    response = client.get_object(Bucket=TENCENT_COS_BUCKET, Key=TENCENT_COS_LATEST_KEY)
    raw = response["Body"].get_raw_stream().read()
    return json.loads(raw.decode("utf-8"))


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


def get_request_api_key():
    return request.headers.get("X-API-Key")


def get_api_role():
    api_key = get_request_api_key()
    if ADMIN_API_KEY and api_key == ADMIN_API_KEY:
        return AUTH_ADMIN
    if CLIENT_API_KEY and api_key == CLIENT_API_KEY:
        return AUTH_CLIENT
    if api_key in LEGACY_CLIENT_KEYS:
        return AUTH_LEGACY
    return None


def require_api_role(*allowed_roles):
    role = get_api_role()
    if role in allowed_roles:
        return role, None
    return None, (jsonify({"status": "failure", "message": "Unauthorized"}), 401)


def get_client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr


def write_audit(
    action,
    license_key=None,
    old_hwid=None,
    new_hwid=None,
    old_expire_at=None,
    new_expire_at=None,
    detail=None,
):
    """Best-effort audit log. Failures here must never block licensing."""
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        if not conn:
            return
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS "LicenseAuditLogs" (
                id SERIAL PRIMARY KEY,
                action TEXT NOT NULL,
                license_key TEXT,
                old_hwid TEXT,
                new_hwid TEXT,
                client_ip TEXT,
                user_agent TEXT,
                old_expire_at TIMESTAMPTZ,
                new_expire_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                detail TEXT
            )
            """
        )
        cur.execute(
            """
            INSERT INTO "LicenseAuditLogs"
                (action, license_key, old_hwid, new_hwid, client_ip, user_agent,
                 old_expire_at, new_expire_at, created_at, detail)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                action,
                license_key,
                old_hwid,
                new_hwid,
                get_client_ip(),
                request.headers.get("User-Agent", ""),
                old_expire_at,
                new_expire_at,
                datetime.now(timezone.utc),
                json.dumps(detail or {}, ensure_ascii=False),
            ),
        )
        conn.commit()
    except Exception as e:
        print(f"Audit log skipped: {e}")
        if conn:
            conn.rollback()
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


def get_hwid_candidates(data):
    old_hwid = data.get("old_hwid")
    old_hwid_candidates = data.get("old_hwid_candidates") or []
    if not isinstance(old_hwid_candidates, list):
        old_hwid_candidates = []
    return [value for value in [old_hwid, *old_hwid_candidates] if value]


# ===================================================================
# K7 / 91 script license API
# ===================================================================


@app.route("/check_update", methods=["POST"])
def check_update():
    role, auth_error = require_api_role(AUTH_ADMIN, AUTH_CLIENT, AUTH_LEGACY)
    if auth_error:
        write_audit("check_update_unauthorized", detail={"path": request.path})
        return auth_error

    data = request.get_json(silent=True) or {}
    current_version = str(data.get("current_version") or data.get("app_version") or "").strip()

    try:
        manifest = read_update_manifest()
        remote_version = str(manifest.get("version") or "").strip()
        object_key = str(manifest.get("key") or "").strip()

        if not remote_version or not object_key:
            return jsonify({"status": "failure", "message": "Invalid update manifest"}), 500

        update_available = current_version != remote_version
        download_url = None
        if update_available:
            client = get_cos_client()
            download_url = client.get_presigned_url(
                Method="GET",
                Bucket=TENCENT_COS_BUCKET,
                Key=object_key,
                Expired=UPDATE_URL_EXPIRE_SECONDS,
            )

        return jsonify(
            {
                "status": "success",
                "version": remote_version,
                "current_version": current_version,
                "update_available": update_available,
                "download_url": download_url,
                "filename": manifest.get("filename"),
                "key": object_key,
                "sha256": manifest.get("sha256"),
                "size": manifest.get("size"),
                "force": bool(manifest.get("force", False)),
                "notes": manifest.get("notes", []),
                "url_expires_in": UPDATE_URL_EXPIRE_SECONDS if download_url else 0,
            }
        ), 200
    except Exception as e:
        write_audit(
            "check_update_server_error",
            detail={"role": role, "current_version": current_version, "error": str(e)},
        )
        return jsonify({"status": "failure", "message": str(e)}), 500


@app.route("/verify", methods=["POST"])
def verify_key():
    role, auth_error = require_api_role(AUTH_ADMIN, AUTH_CLIENT, AUTH_LEGACY)
    if auth_error:
        write_audit("verify_unauthorized", detail={"path": request.path})
        return auth_error

    data = request.get_json(silent=True) or {}
    key = data.get("key")
    hwid = data.get("hwid")
    script_id = data.get("script_id")
    app_version = data.get("app_version")

    if not all([key, hwid, script_id]):
        write_audit(
            "verify_bad_request",
            license_key=key,
            new_hwid=hwid,
            detail={"role": role, "app_version": app_version},
        )
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
            write_audit(
                "verify_invalid_key",
                license_key=key,
                new_hwid=hwid,
                detail={"role": role, "script_id": script_id, "app_version": app_version},
            )
            return jsonify({"status": "failure", "message": "Invalid license key"}), 200

        stored_hwid, expires_at, stored_script_type, duration_days = result
        expires_at_utc = as_utc(expires_at)
        now = datetime.now(timezone.utc)

        if stored_script_type != script_id:
            write_audit(
                "verify_script_mismatch",
                license_key=key,
                old_hwid=stored_hwid,
                new_hwid=hwid,
                old_expire_at=expires_at,
                detail={
                    "role": role,
                    "script_id": script_id,
                    "stored_script_type": stored_script_type,
                    "app_version": app_version,
                },
            )
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
                write_audit(
                    "verify_activated",
                    license_key=key,
                    new_hwid=hwid,
                    new_expire_at=new_expire_at,
                    detail={"role": role, "duration_days": duration_days, "app_version": app_version},
                )
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
                write_audit(
                    "verify_rebound",
                    license_key=key,
                    new_hwid=hwid,
                    old_expire_at=expires_at,
                    new_expire_at=expires_at,
                    detail={"role": role, "app_version": app_version},
                )
                message = {
                    "status": "success",
                    "message": "Bound successfully",
                    "expires_at": iso_z(expires_at),
                }
            else:
                write_audit(
                    "verify_invalid_or_expired_activation",
                    license_key=key,
                    new_hwid=hwid,
                    old_expire_at=expires_at,
                    detail={"role": role, "duration_days": duration_days, "app_version": app_version},
                )
                message = {"status": "failure", "message": "License is invalid or expired"}

        else:
            legacy_hwids = set(get_hwid_candidates(data))
            is_migrating_hwid = stored_hwid != hwid and stored_hwid in legacy_hwids

            if stored_hwid != hwid and not is_migrating_hwid:
                write_audit(
                    "verify_hwid_mismatch",
                    license_key=key,
                    old_hwid=stored_hwid,
                    new_hwid=hwid,
                    old_expire_at=expires_at,
                    detail={
                        "role": role,
                        "legacy_candidates_count": len(legacy_hwids),
                        "app_version": app_version,
                    },
                )
                message = {"status": "failure", "message": "HWID mismatch"}
            elif expires_at_utc is None:
                write_audit(
                    "verify_missing_expiry",
                    license_key=key,
                    old_hwid=stored_hwid,
                    new_hwid=hwid,
                    detail={"role": role, "app_version": app_version},
                )
                message = {"status": "failure", "message": "License state error: missing expiry"}
            elif expires_at_utc < now:
                write_audit(
                    "verify_expired",
                    license_key=key,
                    old_hwid=stored_hwid,
                    new_hwid=hwid,
                    old_expire_at=expires_at,
                    detail={"role": role, "app_version": app_version},
                )
                message = {"status": "failure", "message": "License expired"}
            else:
                if is_migrating_hwid:
                    cur.execute(
                        'UPDATE "LicenseKeys" SET hwid = %s WHERE key = %s AND hwid = %s',
                        (hwid, key, stored_hwid),
                    )
                    conn.commit()
                    print(f"Migrated license {key} from legacy hwid to new hwid")
                    write_audit(
                        "verify_hwid_migrated",
                        license_key=key,
                        old_hwid=stored_hwid,
                        new_hwid=hwid,
                        old_expire_at=expires_at,
                        new_expire_at=expires_at,
                        detail={"role": role, "app_version": app_version},
                    )
                else:
                    write_audit(
                        "verify_success",
                        license_key=key,
                        old_hwid=stored_hwid,
                        new_hwid=hwid,
                        old_expire_at=expires_at,
                        new_expire_at=expires_at,
                        detail={"role": role, "app_version": app_version},
                    )
                message = {
                    "status": "success",
                    "message": "Verified successfully",
                    "expires_at": iso_z(expires_at),
                }

        return jsonify(message), 200

    except Exception as e:
        conn.rollback()
        write_audit(
            "verify_server_error",
            license_key=key,
            new_hwid=hwid,
            detail={"role": role, "app_version": app_version, "error": str(e)},
        )
        return jsonify({"status": "failure", "message": str(e)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/unbind", methods=["POST"])
def unbind_key():
    role, auth_error = require_api_role(AUTH_ADMIN, AUTH_CLIENT, AUTH_LEGACY)
    if auth_error:
        write_audit("unbind_unauthorized", detail={"path": request.path})
        return auth_error

    data = request.get_json(silent=True) or {}
    key = data.get("key")
    hwid = data.get("hwid")
    app_version = data.get("app_version")

    if not key or not hwid:
        write_audit(
            "unbind_bad_request",
            license_key=key,
            new_hwid=hwid,
            detail={"role": role, "app_version": app_version},
        )
        return jsonify({"status": "failure", "message": "Missing parameters"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"status": "failure", "message": "Database connection error"}), 500

    cur = conn.cursor()
    try:
        # Self-service unbind: the provided key and current hwid must match.
        # This preserves compatibility without letting clients alter expiry dates.
        cur.execute(
            'SELECT hwid, "expireAt" FROM "LicenseKeys" WHERE key = %s',
            (key,),
        )
        result = cur.fetchone()
        if not result:
            write_audit(
                "unbind_invalid_key",
                license_key=key,
                new_hwid=hwid,
                detail={"role": role, "app_version": app_version},
            )
            return jsonify({"status": "failure", "message": "Unbind failed or not found"}), 200

        stored_hwid, expires_at = result
        if stored_hwid != hwid:
            write_audit(
                "unbind_hwid_mismatch",
                license_key=key,
                old_hwid=stored_hwid,
                new_hwid=hwid,
                old_expire_at=expires_at,
                detail={"role": role, "app_version": app_version},
            )
            return jsonify({"status": "failure", "message": "Unbind failed or not found"}), 200

        cur.execute(
            'UPDATE "LicenseKeys" SET hwid = NULL WHERE key = %s AND hwid = %s',
            (key, hwid),
        )
        conn.commit()
        if cur.rowcount > 0:
            write_audit(
                "unbind_success",
                license_key=key,
                old_hwid=stored_hwid,
                old_expire_at=expires_at,
                new_expire_at=expires_at,
                detail={"role": role, "app_version": app_version},
            )
        else:
            write_audit(
                "unbind_noop",
                license_key=key,
                old_hwid=stored_hwid,
                new_hwid=hwid,
                old_expire_at=expires_at,
                detail={"role": role, "app_version": app_version},
            )
        message = (
            {"status": "success", "message": "Unbound successfully"}
            if cur.rowcount > 0
            else {"status": "failure", "message": "Unbind failed or not found"}
        )
        return jsonify(message), 200
    except Exception as e:
        conn.rollback()
        write_audit(
            "unbind_server_error",
            license_key=key,
            new_hwid=hwid,
            detail={"role": role, "app_version": app_version, "error": str(e)},
        )
        return jsonify({"status": "failure", "message": str(e)}), 500
    finally:
        cur.close()
        conn.close()


# ===================================================================
# Transaction log API
# ===================================================================


@app.route("/log_transaction", methods=["POST"])
def log_transaction():
    role, auth_error = require_api_role(AUTH_ADMIN, AUTH_CLIENT, AUTH_LEGACY)
    if auth_error:
        write_audit("transaction_log_unauthorized", detail={"path": request.path})
        return auth_error

    data = request.get_json(silent=True) or {}
    license_key = data.get("license_key")
    client_account = data.get("client_account")
    trans_type = data.get("type")
    amount = data.get("amount")
    app_version = data.get("app_version")

    if not license_key:
        write_audit(
            "transaction_log_bad_request",
            detail={"role": role, "client_account": client_account, "app_version": app_version},
        )
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
        write_audit(
            "transaction_log_success",
            license_key=license_key,
            detail={
                "role": role,
                "client_account": client_account,
                "transaction_type": trans_type,
                "amount": amount,
                "app_version": app_version,
            },
        )
        return jsonify({"status": "success", "message": "Log saved successfully"}), 200
    except Exception as e:
        conn.rollback()
        print(f"Failed to save transaction log: {e}")
        write_audit(
            "transaction_log_failure",
            license_key=license_key,
            detail={
                "role": role,
                "client_account": client_account,
                "transaction_type": trans_type,
                "amount": amount,
                "app_version": app_version,
                "error": str(e),
            },
        )
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
