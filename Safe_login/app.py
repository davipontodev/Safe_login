import os
import subprocess
import sys
import sqlite3
import webbrowser
from threading import Timer

for pacote in ["flask", "bcrypt"]:
    try:
        __import__(pacote)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pacote])

import bcrypt
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = "chave_secreta_sistema_login"


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

    session["user_id"] = user["id"]
    session["user_name"] = user["name"]
    session["user_email"] = user["email"]
    session["user_role"] = user["role"]

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