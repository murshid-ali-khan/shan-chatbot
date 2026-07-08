from flask import Flask, request, jsonify, send_from_directory, session, redirect
from flask_cors import CORS
import requests
import os
import psycopg2
import psycopg2.extras
import bcrypt
from datetime import timedelta
from tavily import TavilyClient
TAVILY_API_KEY = os.environ.get("TAVILY_API_KEY", "")

app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get("SECRET_KEY", "change_this_secret_key_123!")
app.permanent_session_lifetime = timedelta(days=7)
CORS(app, supports_credentials=True)

GROQ_API_KEY        = os.environ.get("GROQ_API_KEY", "")
GROQ_API_URL        = "https://api.groq.com/openai/v1/chat/completions"
CF_TURNSTILE_SECRET = os.environ.get("CF_TURNSTILE_SECRET", "your_turnstile_secret_here")
DATABASE_URL        = os.environ.get("DATABASE_URL", "")

def get_db():
    return psycopg2.connect(DATABASE_URL, sslmode='require')

def init_db():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS chats (
            id VARCHAR(50) PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            title VARCHAR(200) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            chat_id VARCHAR(50) REFERENCES chats(id) ON DELETE CASCADE,
            role VARCHAR(20) NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit(); cur.close(); conn.close()

try:
    init_db()
    print("✅ Database ready")
except Exception as e:
    print(f"⚠️ DB error: {e}")
    pass

def verify_turnstile(token, ip):
    try:
        r = requests.post("https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={"secret": CF_TURNSTILE_SECRET, "response": token, "remoteip": ip}, timeout=10)
        return r.json().get("success", False)
    except:
        return False

# ── Pages ──
@app.route("/")
def welcome():
    return send_from_directory("static", "welcome.html")

@app.route("/login")
def login_page():
    return send_from_directory("static", "login.html")

@app.route("/register")
def register_page():
    return send_from_directory("static", "register.html")

@app.route("/chat")
def chat_page():
    if "user_id" not in session:
        return redirect("/login")
    return send_from_directory("static", "chat.html")

# ── Auth ──
@app.route("/api/register", methods=["POST"])
def api_register():
    data     = request.json
    username = data.get("username","").strip()
    email    = data.get("email","").strip().lower()
    password = data.get("password","")
    cf_token = data.get("cf_token","")

    if not all([username, email, password, cf_token]):
        return jsonify({"error": "All fields are required"}), 400
    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    ip = request.headers.get("CF-Connecting-IP", request.remote_addr)
    if not verify_turnstile(cf_token, ip):
        return jsonify({"error": "Security check failed. Please try again."}), 400

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("INSERT INTO users (username, email, password_hash) VALUES (%s,%s,%s) RETURNING id",
                    (username, email, pw_hash))
        user_id = cur.fetchone()[0]
        conn.commit(); cur.close(); conn.close()
        session.permanent = True
        session["user_id"] = user_id
        session["username"] = username
        return jsonify({"success": True, "username": username})
    except psycopg2.errors.UniqueViolation:
        return jsonify({"error": "Username or email already exists"}), 409
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/login", methods=["POST"])
def api_login():
    data     = request.json
    email    = data.get("email","").strip().lower()
    password = data.get("password","")
    if not all([email, password]):
        return jsonify({"error": "Email and password required"}), 400
    try:
        conn = get_db(); cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone(); cur.close(); conn.close()
        if not user or not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
            return jsonify({"error": "Invalid email or password"}), 401
        session.permanent = True
        session["user_id"]  = user["id"]
        session["username"] = user["username"]
        return jsonify({"success": True, "username": user["username"]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"success": True})

@app.route("/api/me")
def api_me():
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401
    return jsonify({"user_id": session["user_id"], "username": session["username"]})

# ── Chats ──
@app.route("/api/chats", methods=["GET"])
def get_chats():
    if "user_id" not in session: return jsonify({"error": "Unauthorized"}), 401
    try:
        conn = get_db(); cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM chats WHERE user_id=%s ORDER BY updated_at DESC", (session["user_id"],))
        chats = cur.fetchall(); cur.close(); conn.close()
        return jsonify([dict(c) for c in chats])
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/chats", methods=["POST"])
def create_chat():
    if "user_id" not in session: return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("INSERT INTO chats (id, user_id, title) VALUES (%s,%s,%s)",
                    (data["id"], session["user_id"], data.get("title","New Chat")))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"success": True})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/chats/<chat_id>", methods=["DELETE"])
def delete_chat(chat_id):
    if "user_id" not in session: return jsonify({"error": "Unauthorized"}), 401
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("DELETE FROM chats WHERE id=%s AND user_id=%s", (chat_id, session["user_id"]))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"success": True})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/chats/<chat_id>/messages", methods=["GET"])
def get_messages(chat_id):
    if "user_id" not in session: return jsonify({"error": "Unauthorized"}), 401
    try:
        conn = get_db(); cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT role, content FROM messages WHERE chat_id=%s ORDER BY created_at", (chat_id,))
        msgs = cur.fetchall(); cur.close(); conn.close()
        return jsonify([dict(m) for m in msgs])
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/chats/<chat_id>/messages", methods=["POST"])
def save_message(chat_id):
    if "user_id" not in session: return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("INSERT INTO messages (chat_id, role, content) VALUES (%s,%s,%s)",
                    (chat_id, data["role"], data["content"]))
        cur.execute("UPDATE chats SET updated_at=CURRENT_TIMESTAMP WHERE id=%s", (chat_id,))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"success": True})
    except Exception as e: return jsonify({"error": str(e)}), 500

# ── Groq ──

@app.route("/chat-api", methods=["POST"])
def chat_api():
    if "user_id" not in session: return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    messages = data.get("messages", [])
    if not messages: return jsonify({"error": "No messages"}), 400

    # Search web for latest info
    web_context = ""
    try:
        if TAVILY_API_KEY:
            tavily = TavilyClient(api_key=TAVILY_API_KEY)
            last_message = messages[-1]["content"]
            keywords = ["today", "now", "current", "2024", "2025", "2026", "2027" 
                        "latest", "news", "price", "score", "winner", "recent"]
            should_search = any(k in last_message.lower() for k in keywords)
            
            if should_search:
                search = tavily.search(query=last_message, max_results=3)
            
            web_context = "\n".join([f"- {r['content']}" for r in search["results"]])
    except:
        pass

    system_prompt = "You are a helpful, friendly assistant. Answer clearly and concisely."
    if web_context:
        system_prompt += f"\n\nLatest web information:\n{web_context}\n\nUse this to answer with current 2026 data."

    try:
        res = requests.post(GROQ_API_URL,
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={"model": "llama-3.3-70b-versatile",
                  "messages": [{"role":"system","content": system_prompt}, *messages],
                  "temperature": 0.7, "max_tokens": 1024},
            timeout=60)
        result = res.json()
        if res.status_code != 200:
            return jsonify({"error": result.get("error",{}).get("message","API error")}), 500
        return jsonify({"reply": result["choices"][0]["message"]["content"]})
    except Exception as e: return jsonify({"error": str(e)}), 500
@app.route("/admin/stats")
def admin_stats():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    users = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM chats")
    chats = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM messages")
    messages = cur.fetchone()[0]
    cur.execute("SELECT username, email, created_at FROM users ORDER BY created_at DESC")
    user_list = cur.fetchall()
    cur.close(); conn.close()
    return jsonify({
        "total_users": users,
        "total_chats": chats,
        "total_messages": messages,
        "users": [{"username": u[0], "email": u[1], "joined": str(u[2])} for u in user_list]
    })
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=False)
