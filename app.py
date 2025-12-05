import os
from flask import Flask, request, jsonify
import psycopg2
from datetime import datetime, timezone, timedelta

app = Flask(__name__)

# --- 从环境变量中读取密钥和数据库地址 ---
DATABASE_URL = os.environ.get("DATABASE_URL")
MASTER_KEY = os.environ.get("MASTER_KEY") 

def get_db_connection():
    """建立数据库连接"""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print(f"数据库连接失败: {e}")
        return None

# ===================================================================
#  K7 / 91 脚本的授权 API
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
    if not conn: return jsonify({"status": "failure", "message": "数据库连接错误"}), 500
    
    cur = conn.cursor()
    
    try:
        cur.execute(
            'SELECT hwid, "expireAt", "script_type", "duration_days" FROM "LicenseKeys" WHERE key = %s', 
            (key,)
        )
        result = cur.fetchone()
        
        if not result:
            return jsonify({"status": "failure", "message": "卡密无效"}), 200

        stored_hwid, expires_at, stored_script_type, duration_days = result

        # 检查脚本类型
        if stored_script_type != script_id:
            return jsonify({"status": "failure", "message": "卡密类型不匹配"}), 200

        # --- 首次激活流程 ---
        if stored_hwid is None:
            print(f"--- 激活请求: 卡密 {key} 正在被 {hwid} 首次激活 ---")
            
            # 时长卡激活
            if duration_days and duration_days > 0:
                new_expire_at = datetime.now(timezone.utc) + timedelta(days=duration_days)
                cur.execute(
                    'UPDATE "LicenseKeys" SET hwid = %s, "expireAt" = %s WHERE key = %s',
                    (hwid, new_expire_at, key)
                )
                conn.commit()
                expires_at_iso = new_expire_at.isoformat().replace('+00:00', 'Z')
                message = {"status": "success", "message": f"激活成功，有效期 {duration_days} 天", "expires_at": expires_at_iso}
            
            # 测试卡/固定日期卡激活
            elif expires_at and expires_at.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
                cur.execute(
                    'UPDATE "LicenseKeys" SET hwid = %s WHERE key = %s', 
                    (hwid, key)
                )
                conn.commit()
                expires_at_iso = expires_at.isoformat().replace('+00:00', 'Z')
                message = {"status": "success", "message": "绑定成功", "expires_at": expires_at_iso}
            
            else:
                message = {"status": "failure", "message": "卡密配置错误或已过期"}
        
        # --- 常规验证流程 ---
        else:
            if stored_hwid != hwid:
                message = {"status": "failure", "message": "硬件ID不匹配"}
            elif expires_at is None:
                message = {"status": "failure", "message": "卡密状态异常"}
            elif expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
                message = {"status": "failure", "message": "授权已过期"}
            else:
                expires_at_iso = expires_at.isoformat().replace('+00:00', 'Z')
                message = {"status": "success", "message": "验证成功", "expires_at": expires_at_iso}
        
        return jsonify(message), 200

    except Exception as e:
        return jsonify({"status": "failure", "message": str(e)}), 500
    finally:
        cur.close()
        conn.close()


@app.route('/unbind', methods=['POST'])
def unbind_key():
    if request.headers.get('X-API-Key') != MASTER_KEY:
        return jsonify({"status": "failure", "message": "无效的 API 密钥"}), 401
    
    data = request.get_json()
    key, hwid = data.get('key'), data.get('hwid')
    
    if not key or not hwid: 
        return jsonify({"status": "failure", "message": "缺少参数"}), 400
    
    conn = get_db_connection()
    if not conn: return jsonify({"status": "failure", "message": "数据库连接错误"}), 500

    cur = conn.cursor()
    try:
        cur.execute('UPDATE "LicenseKeys" SET hwid = NULL WHERE key = %s AND hwid = %s', (key, hwid))
        conn.commit()
        message = {"status": "success", "message": "解绑成功"} if cur.rowcount > 0 else {"status": "failure", "message": "解绑失败或未找到"}
        return jsonify(message), 200
    except Exception as e:
        return jsonify({"status": "failure", "message": str(e)}), 500
    finally:
        cur.close()
        conn.close()

# ===================================================================
#  【新增】 交易日志记录接口
# ===================================================================

@app.route('/log_transaction', methods=['POST'])
def log_transaction():
    """
    接收客户端上传的交易记录
    数据包括：license_key(来源), client_account(客户), type(上/下分), amount(数额)
    """
    # 1. 验证 API Key (安全防护)
    if request.headers.get('X-API-Key') != MASTER_KEY:
        return jsonify({"status": "failure", "message": "Unauthorized"}), 401

    # 2. 获取数据
    data = request.get_json()
    license_key = data.get('license_key')
    client_account = data.get('client_account')
    trans_type = data.get('type')   # 对应数据库 transaction_type
    amount = data.get('amount')     # 对应数据库 amount

    # 3. 简单校验
    if not license_key:
        return jsonify({"status": "failure", "message": "Missing license key"}), 400

    conn = get_db_connection()
    if not conn: return jsonify({"status": "failure", "message": "Database error"}), 500

    cur = conn.cursor()
    try:
        # 执行插入操作
        # 注意：表名 "TransactionLogs" 需要加双引号，因为 PostgreSQL 对大小写敏感
        cur.execute(
            'INSERT INTO "TransactionLogs" (license_key, client_account, transaction_type, amount) VALUES (%s, %s, %s, %s)',
            (license_key, client_account, trans_type, amount)
        )
        conn.commit()
        return jsonify({"status": "success", "message": "Log saved successfully"}), 200
    except Exception as e:
        conn.rollback()
        print(f"写入日志失败: {e}")
        return jsonify({"status": "failure", "message": str(e)}), 500
    finally:
        cur.close()
        conn.close()

# ===================================================================
#  旧的充值客户端 API (保留以兼容旧系统，如果不需要可删除)
# ===================================================================

@app.route('/api/create_user', methods=['POST'])
def create_user():
    data = request.get_json()
    license_key, password = data.get('license_key'), data.get('password')
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('INSERT INTO "user" (license_key, password) VALUES (%s, %s)', (license_key, password))
        conn.commit()
        return jsonify({"status": "success", "message": "创建成功"}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"status": "failure", "message": str(e)}), 500
    finally:
        cur.close(); conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    license_key, password = data.get('license_key'), data.get('password')
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('SELECT password FROM "user" WHERE license_key = %s', (license_key,))
        user = cur.fetchone()
        if user and user[0] == password:
            return jsonify({"status": "success", "message": "登录成功"}), 200
        return jsonify({"status": "failure", "message": "验证失败"}), 401
    finally:
        cur.close(); conn.close()

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=10000)