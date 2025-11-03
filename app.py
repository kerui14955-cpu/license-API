# 文件: app.py (【已修改】 - 支持首次激活)
import os
from flask import Flask, request, jsonify
import psycopg2
from datetime import datetime, timezone, timedelta # 【新增】导入 timedelta

app = Flask(__name__)

# --- 从环境变量中读取密钥和数据库地址 ---
DATABASE_URL = os.environ.get("DATABASE_URL")
MASTER_KEY = os.environ.get("MASTER_KEY") 

def get_db_connection():
    """建立数据库连接"""
    conn = psycopg2.connect(DATABASE_URL)
    return conn

# ===================================================================
#  K7 / 91 脚本的授权 API (【已修改】)
# ===================================================================

# ▼▼▼ 用下面的新版本，完整替换你原来的 verify_key 函数 ▼▼▼
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
    
    # 【修改】: 增加 "duration_days" 字段
    cur.execute(
        'SELECT hwid, "expireAt", "script_type", "duration_days" FROM "LicenseKeys" WHERE key = %s', 
        (key,)
    )
    result = cur.fetchone()
    
    if not result:
        cur.close(); conn.close()
        return jsonify({"status": "failure", "message": "卡密无效"}), 200

    # 【修改】: 解包新字段
    stored_hwid, expires_at, stored_script_type, duration_days = result

    # 检查脚本类型
    if stored_script_type != script_id:
        cur.close(); conn.close()
        return jsonify({"status": "failure", "message": "卡密类型不匹配"}), 200

    # 【核心修改】: 检查激活状态
    if stored_hwid is None:
        # --- 首次激活流程 ---
        print(f"--- 激活请求: 卡密 {key} 正在被 {hwid} 首次激活 ---")
        
        # 检查是"时长卡" (duration_days > 0) 还是"即时卡" (duration_days is 0 or None, 但 expireAt 已设置)
        if duration_days and duration_days > 0:
            # 这是标准的 "时长卡" 激活
            new_expire_at = datetime.now(timezone.utc) + timedelta(days=duration_days)
            
            cur.execute(
                'UPDATE "LicenseKeys" SET hwid = %s, "expireAt" = %s WHERE key = %s',
                (hwid, new_expire_at, key)
            )
            conn.commit()
            print(f"--- 激活成功: {key} 的到期时间设置为 {new_expire_at} ---")
            
            expires_at_iso = new_expire_at.isoformat().replace('+00:00', 'Z')
            message = {"status": "success", "message": f"激活成功，有效期 {duration_days} 天", "expires_at": expires_at_iso}
        
        elif expires_at and expires_at.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
            # 这是 "测试卡" (如1分钟卡)，它有 expireAt 但没有 duration
            # 只需要绑定 hwid
            cur.execute(
                'UPDATE "LicenseKeys" SET hwid = %s WHERE key = %s', 
                (hwid, key)
            )
            conn.commit()
            print(f"--- 激活成功: {key} (测试卡) 绑定到 {hwid} ---")
            
            expires_at_iso = expires_at.isoformat().replace('+00:00', 'Z')
            message = {"status": "success", "message": "测试卡密绑定成功", "expires_at": expires_at_iso}
        
        else:
            # 卡密既没有 duration_days，也没有有效的 expires_at (可能是已过期的测试卡)
            message = {"status": "failure", "message": "卡密无效或已过期 (无法激活)"}
    
    else:
        # --- 已激活，常规验证流程 ---
        
        # 检查 HWID
        if stored_hwid != hwid:
            message = {"status": "failure", "message": "硬件ID不匹配"}
        
        # 检查到期时间 (安全检查)
        elif expires_at is None:
            message = {"status": "failure", "message": "卡密状态异常 (缺少到期日)"}
        
        # 检查到期时间 (常规)
        elif expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            message = {"status": "failure", "message": "授权已过期"}
        
        # 全部通过
        else:
            expires_at_iso = expires_at.isoformat().replace('+00:00', 'Z')
            message = {"status": "success", "message": "验证成功", "expires_at": expires_at_iso}
    
    # 返回结果
    cur.close(); conn.close()
    return jsonify(message), 200
# ▲▲▲ 替换结束 ▲▲▲


@app.route('/unbind', methods=['POST'])
def unbind_key():
    # (此函数保持不变)
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
#  充值客户端的 API (这部分保持不变)
# ===================================================================

@app.route('/api/create_user', methods=['POST'])
def create_user():
    data = request.get_json()
    license_key, password = data.get('license_key'), data.get('password')
    if not license_key or not password:
        return jsonify({"status": "failure", "message": "卡密和密码不能为空"}), 400
    
    password_to_store = password
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            'INSERT INTO "user" (license_key, password) VALUES (%s, %s)',
            (license_key, password_to_store)
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
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT password FROM "user" WHERE license_key = %s', (license_key,))
    user = cur.fetchone()
    cur.close(); conn.close()
    
    if user and user[0] == password:
        return jsonify({"status": "success", "message": "登录成功", "user": {"license_key": license_key}}), 200
    else:
        return jsonify({"status": "failure", "message": "卡密或密码错误"}), 401

@app.route('/api/log_recharge', methods=['POST'])
def log_recharge_entry():
    data = request.get_json()
    license_key, game_account = data.get('license_key'), data.get('game_account')
    if not license_key or not game_account:
        return jsonify({"status": "failure", "message": "缺少 license_key 或 game_account"}), 400
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('SELECT id FROM "user" WHERE license_key = %s', (license_key,))
        user_record = cur.fetchone()
        if not user_record:
            return jsonify({"status": "failure", "message": "记录失败：找不到对应的用户卡密"}), 404
        user_id = user_record[0]
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