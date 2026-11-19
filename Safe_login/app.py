import json
import os
import secrets
import subprocess
import sys
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from threading import Timer

for pacote in ["flask", "bcrypt"]:
    try:
        __import__(pacote)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pacote])

import bcrypt
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "chave_secreta_sistema_login")
# Necessário atrás do proxy HTTPS do Render para gerar URLs com https://
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"


def get_db():
    con = sqlite3.connect("app.db")
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with get_db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user'
            )
        """)


init_db()


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html", tela="cadastro")


@app.route("/entrar")
def tela_login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html", tela="login")


@app.route("/cadastrar", methods=["POST"])
def cadastrar():
    nome = request.form.get("nome")
    email = request.form.get("email")
    senha = request.form.get("senha")

    hash_senha = bcrypt.hashpw(senha.encode(), bcrypt.gensalt()).decode()

    with get_db() as con:
        total = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        role = "admin" if total == 0 else "user"

        try:
            con.execute(
                "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)",
                (nome, email, hash_senha, role),
            )
            con.commit()
            flash("Conta criada com sucesso! Faça login para continuar.", "success")
            return redirect(url_for("tela_login"))
        except sqlite3.IntegrityError:
            flash("Esse e-mail já está cadastrado.", "error")
            return redirect(url_for("index"))


@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email")
    senha = request.form.get("senha")

    with get_db() as con:
        user = con.execute(
            "SELECT id, name, email, password_hash, role FROM users WHERE email = ?",
            (email,),
        ).fetchone()

    if not user or not bcrypt.checkpw(senha.encode(), user["password_hash"].encode()):
        flash("E-mail ou senha inválidos.", "error")
        return redirect(url_for("tela_login"))

    iniciar_sessao(user)
    return redirect(url_for("dashboard"))


def iniciar_sessao(user):
    session["user_id"] = user["id"]
    session["user_name"] = user["name"]
    session["user_email"] = user["email"]
    session["user_role"] = user["role"]


@app.route("/login/google")
def login_google():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        flash("Login com Google ainda não foi configurado.", "error")
        return redirect(url_for("tela_login"))

    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": url_for("google_callback", _external=True),
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "prompt": "select_account",
    }
    return redirect(f"{GOOGLE_AUTH_URL}?{urllib.parse.urlencode(params)}")


@app.route("/login/google/callback")
def google_callback():
    state = session.pop("oauth_state", None)
    if not state or request.args.get("state") != state or "code" not in request.args:
        flash("Não foi possível entrar com o Google. Tente novamente.", "error")
        return redirect(url_for("tela_login"))

    try:
        dados_token = urllib.parse.urlencode({
            "code": request.args["code"],
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": url_for("google_callback", _external=True),
            "grant_type": "authorization_code",
        }).encode()
        with urllib.request.urlopen(GOOGLE_TOKEN_URL, data=dados_token, timeout=10) as resp:
            access_token = json.load(resp)["access_token"]

        req = urllib.request.Request(
            GOOGLE_USERINFO_URL, headers={"Authorization": f"Bearer {access_token}"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            perfil = json.load(resp)
    except (urllib.error.URLError, KeyError, ValueError):
        flash("Não foi possível entrar com o Google. Tente novamente.", "error")
        return redirect(url_for("tela_login"))

    email = perfil.get("email")
    if not email or not perfil.get("email_verified"):
        flash("Sua conta Google não tem um e-mail verificado.", "error")
        return redirect(url_for("tela_login"))

    with get_db() as con:
        user = con.execute(
            "SELECT id, name, email, role FROM users WHERE email = ?", (email,)
        ).fetchone()

        if not user:
            total = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            role = "admin" if total == 0 else "user"
            # Conta criada pelo Google recebe uma senha aleatória: o acesso é feito pelo Google
            senha_aleatoria = bcrypt.hashpw(secrets.token_bytes(32), bcrypt.gensalt()).decode()
            con.execute(
                "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)",
                (perfil.get("name") or email.split("@")[0], email, senha_aleatoria, role),
            )
            con.commit()
            user = con.execute(
                "SELECT id, name, email, role FROM users WHERE email = ?", (email,)
            ).fetchone()

    iniciar_sessao(user)
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("index"))

    usuarios = []
    if session.get("user_role") == "admin":
        with get_db() as con:
            usuarios = con.execute("SELECT id, name, email, role FROM users").fetchall()

    return render_template("dashboard.html", usuarios=usuarios)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


def abrir_navegador():
    webbrowser.open_new("http://127.0.0.1:5000")


if __name__ == "__main__":
    if os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        Timer(1.2, abrir_navegador).start()
    app.run(debug=True)
