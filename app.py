# 文件: app.py
import os
from flask import Flask, request, jsonify
import psycopg2
from datetime import datetime, timezone

app = Flask(__name__)

# --- 安全核心 ---
# 从 Render 的环境变量中读取数据库连接字符串和我们自己设置的主密钥
# 这样，代码中就没有任何敏感信息
DATABASE_URL = os.environ.get("DATABASE_URL")
MASTER_KEY = os.environ.get("MASTER_KEY") 

def get_db_connection():
    """建立数据库连接"""
    conn = psycopg2.connect(DATABASE_URL)
    return conn

@app.before_request
def check_master_key():
    """在处理每个请求前，都验证 Master Key 是否正确"""
    # 客户端必须在请求头中提供 'X-API-Key' 字段
    if request.headers.get('X-API-Key') != MASTER_KEY:
        # 如果密钥不匹配，立即拒绝访问
        return jsonify({"status": "failure", "message": "无效的 API 密钥"}), 401

# --- API 端点 1: 验证卡密 ---
@app.route('/verify', methods=['POST'])
def verify_key():
    data = request.get_json()
    key = data.get('key')
    hwid = data.get('hwid')
    # 【新增】从客户端获取脚本ID
    script_id = data.get('script_id')

    if not key or not hwid or not script_id:
        return jsonify({"status": "failure", "message": "缺少 key, hwid 或 script_id 参数"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    
    # 【修改】查询语句增加了 "script_type"
    cur.execute('SELECT hwid, "expireAt", "script_type" FROM "LicenseKeys" WHERE key = %s', (key,))
    result = cur.fetchone()
    
    if result:
        stored_hwid, expires_at, stored_script_type = result
        
        # 【新增】检查卡密类型是否匹配
        if stored_script_type != script_id:
            cur.close()
            conn.close()
            return jsonify({"status": "failure", "message": "卡密类型不匹配，无法用于此脚本"}), 200

        # 后续的过期检查和硬件ID绑定逻辑保持不变...
        if expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            cur.close()
            conn.close()
            return jsonify({"status": "failure", "message": "授权已过期"}), 200

        expires_at_iso = expires_at.isoformat().replace('+00:00', 'Z')
        if stored_hwid is None:
            cur.execute('UPDATE "LicenseKeys" SET hwid = %s WHERE key = %s', (hwid, key))
            conn.commit()
            message = {"status": "success", "message": "绑定成功", "expires_at": expires_at_iso}
        elif stored_hwid == hwid:
            message = {"status": "success", "message": "验证成功", "expires_at": expires_at_iso}
        else:
            message = {"status": "failure", "message": "硬件ID不匹配"}
    else:
        message = {"status": "failure", "message": "卡密无效"}

    cur.close()
    conn.close()
    return jsonify(message), 200


# --- API 端点 2: 解绑硬件 ---
@app.route('/unbind', methods=['POST'])
def unbind_key():
    data = request.get_json()
    key = data.get('key')
    hwid = data.get('hwid')

    if not key or not hwid:
        return jsonify({"status": "failure", "message": "缺少 key 或 hwid 参数"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    # 先验证 key 和 hwid 是否匹配，防止恶意解绑
    cur.execute("UPDATE \"LicenseKeys\" SET hwid = NULL WHERE key = %s AND hwid = %s", (key, hwid))
    
    # an 'rowcount' attribute to check how many rows were affected.
    if cur.rowcount > 0:
        conn.commit()
        message = {"status": "success", "message": "解绑成功"}
    else:
        message = {"status": "failure", "message": "解绑失败，卡密或硬件ID不匹配"}
    
    cur.close()
    conn.close()
    return jsonify(message), 200

if __name__ == '__main__':
    # Render 会使用 Gunicorn 启动，这部分仅用于本地测试
    app.run(host="0.0.0.0", port=10000)