# 文件: app.py (【最终合并版 V2】 - 适配您现有的 user 和 game_account_log 表)
import os
from flask import Flask, request, jsonify
import psycopg2
from datetime import datetime, timezone
import hashlib

app = Flask(__name__)

# --- 从环境变量中读取密钥和数据库地址 ---
DATABASE_URL = os.environ.get("DATABASE_URL")
MASTER_KEY = os.environ.get("MASTER_KEY") 

def get_db_connection():
    """建立数据库连接"""
    conn = psycopg2.connect(DATABASE_URL)
    return conn

# ===================================================================
#  K7 / 91 脚本的授权 API (这部分保持不变)
# ===================================================================

@app.route('/verify', methods=['POST'])
def verify_key():
    if request.headers.get('X-API-Key') != MASTER_KEY:
        return jsonify({"status": "failure", "message": "无效的 API 密钥"}), 401
    data = request.get_json()
    key, hwid, script_id = data.get('key'), data.get('hwid'), data.get('script_id')
    if not all([key, hwid, script_id]):
        return jsonify({"status": "failure", "message": "缺少 key, hwid 或 script_id 参数"}), 400
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT hwid, "expireAt", "script_type" FROM "LicenseKeys" WHERE key = %s', (key,))
    result = cur.fetchone()
    message = {}
    if result:
        stored_hwid, expires_at, stored_script_type = result
        if stored_script_type != script_id: message = {"status": "failure", "message": "卡密类型不匹配"}
        elif expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc): message = {"status": "failure", "message": "授权已过期"}
        else:
            expires_at_iso = expires_at.isoformat().replace('+00:00', 'Z')
            if stored_hwid is None:
                cur.execute('UPDATE "LicenseKeys" SET hwid = %s WHERE key = %s', (hwid, key)); conn.commit()
                message = {"status": "success", "message": "绑定成功", "expires_at": expires_at_iso}
            elif stored_hwid == hwid: message = {"status": "success", "message": "验证成功", "expires_at": expires_at_iso}
            else: message = {"status": "failure", "message": "硬件ID不匹配"}
    else: message = {"status": "failure", "message": "卡密无效"}
    cur.close(); conn.close()
    return jsonify(message), 200

@app.route('/unbind', methods=['POST'])
def unbind_key():
    if request.headers.get('X-API-Key') != MASTER_KEY:
        return jsonify({"status": "failure", "message": "无效的 API 密钥"}), 401
    data = request.get_json(); key, hwid = data.get('key'), data.get('hwid')
    if not key or not hwid: return jsonify({"status": "failure", "message": "缺少参数"}), 400
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('UPDATE "LicenseKeys" SET hwid = NULL WHERE key = %s AND hwid = %s', (key, hwid))
    message = {"status": "success", "message": "解绑成功"} if cur.rowcount > 0 else {"status": "failure", "message": "解绑失败"}
    conn.commit(); cur.close(); conn.close()
    return jsonify(message), 200

# ===================================================================
#  充值客户端的 API (【已修正】适配您现有的数据库表)
# ===================================================================

@app.route('/api/create_user', methods=['POST'])
def create_user():
    data = request.get_json()
    license_key, password = data.get('license_key'), data.get('password')
    if not license_key or not password:
        return jsonify({"status": "failure", "message": "卡密和密码不能为空"}), 400
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            'INSERT INTO "user" (license_key, password) VALUES (%s, %s)',
            (license_key, password_hash)
        )
        conn.commit()
        return jsonify({"status": "success", "message": f"用户 {license_key} 创建成功"}), 201
    except psycopg2.IntegrityError:
        conn.rollback()
        return jsonify({"status": "failure", "message": "创建失败：该卡密已存在"}), 409
    except Exception as e:
        conn.rollback()
        return jsonify({"status": "failure", "message": f"服务器错误: {e}"}), 500
    finally:
        cur.close(); conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    license_key, password = data.get('license_key'), data.get('password')
    if not license_key or not password:
        return jsonify({"status": "failure", "message": "卡密和密码不能为空"}), 400
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT password FROM "user" WHERE license_key = %s', (license_key,))
    user = cur.fetchone()
    cur.close(); conn.close()
    
    if user and user[0] == password_hash:
        return jsonify({"status": "success", "message": "登录成功", "user": {"license_key": license_key}}), 200
    else:
        return jsonify({"status": "failure", "message": "卡密或密码错误"}), 401

@app.route('/api/log_recharge', methods=['POST'])
def log_recharge_entry():
    """【最终修正】此函数现在会向您现有的 'game_account_log' 表写入数据"""
    data = request.get_json()
    license_key, game_account = data.get('license_key'), data.get('game_account')
    if not license_key or not game_account:
        return jsonify({"status": "failure", "message": "缺少 license_key 或 game_account"}), 400
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # 步骤1: 先根据 license_key 查找 user_id
        cur.execute('SELECT id FROM "user" WHERE license_key = %s', (license_key,))
        user_record = cur.fetchone()
        
        if not user_record:
            return jsonify({"status": "failure", "message": "记录失败：找不到对应的用户卡密"}), 404
        
        user_id = user_record[0]

        # 【最终修正】步骤2: 使用查到的 user_id 和 account_name 插入到您正确的 "game_account_log" 表
        cur.execute(
            'INSERT INTO "game_account_log" (user_id, account_name) VALUES (%s, %s)',
            (user_id, game_account)
        )
        conn.commit()
        return jsonify({"status": "success", "message": "日志记录成功"}), 200
        
    except Exception as e:
        conn.rollback()
        return jsonify({"status": "failure", "message": f"服务器内部错误: {e}"}), 500
    finally:
        cur.close(); conn.close()

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=10000)