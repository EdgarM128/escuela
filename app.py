"""Sistema de Gestión Académica - Flask. Prioridades: 1) Seguridad 2) Usabilidad 3) Disponibilidad."""
import os, sqlite3, secrets, time
from functools import wraps
from flask import Flask, g, render_template, request, redirect, url_for, session, abort, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    DATABASE=os.environ.get("DATABASE", "escuela.db"),
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS") == "1",
    PERMANENT_SESSION_LIFETIME=1800)  # sesión expira a 30 min
MAX_FALLOS, BLOQUEO = 5, 300
FALLOS = {}  # (usuario, ip) -> [timestamps]

def db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def cerrar(_):
    c = g.pop("db", None)
    if c: c.close()

def init_db():
    c = sqlite3.connect(app.config["DATABASE"])
    c.executescript("""
    CREATE TABLE IF NOT EXISTS usuarios(id INTEGER PRIMARY KEY, usuario TEXT UNIQUE NOT NULL,
      nombre TEXT NOT NULL, clave TEXT NOT NULL, rol TEXT CHECK(rol IN('estudiante','profesor')) NOT NULL);
    CREATE TABLE IF NOT EXISTS materias(id INTEGER PRIMARY KEY, nombre TEXT NOT NULL, horario TEXT,
      profesor_id INTEGER NOT NULL REFERENCES usuarios(id));
    CREATE TABLE IF NOT EXISTS inscripciones(estudiante_id INTEGER REFERENCES usuarios(id),
      materia_id INTEGER REFERENCES materias(id), calificacion REAL CHECK(calificacion BETWEEN 0 AND 10),
      PRIMARY KEY(estudiante_id, materia_id));
    CREATE TABLE IF NOT EXISTS auditoria(id INTEGER PRIMARY KEY, fecha TEXT DEFAULT CURRENT_TIMESTAMP,
      profesor_id INTEGER, estudiante_id INTEGER, materia_id INTEGER, anterior REAL, nuevo REAL);
    CREATE INDEX IF NOT EXISTS ix_insc_mat ON inscripciones(materia_id);""")
    if not c.execute("SELECT 1 FROM usuarios").fetchone():
        h = generate_password_hash("Demo2026!")  # CAMBIAR en producción
        for u, n, r in [("prof.garcia","Laura García","profesor"),("prof.lopez","Marco López","profesor"),
                        ("a1001","Ana Torres","estudiante"),("a1002","Luis Pérez","estudiante"),
                        ("a1003","Sofía Ruiz","estudiante"),("a1004","Diego Mora","estudiante")]:
            c.execute("INSERT INTO usuarios(usuario,nombre,clave,rol) VALUES(?,?,?,?)", (u, n, h, r))
        c.executemany("INSERT INTO materias(nombre,horario,profesor_id) VALUES(?,?,?)",
            [("Excel Avanzado","Lun/Mié 18:00",1),("Programación Básica","Mar/Jue 17:00",1),("Inglés Técnico","Vie 16:00",2)])
        c.executemany("INSERT INTO inscripciones VALUES(?,?,?)",
            [(3,1,9.0),(3,2,8.5),(3,3,None),(4,1,7.0),(4,3,8.0),(5,2,9.5),(5,3,10.0),(6,1,6.5),(6,2,None)])
    c.commit(); c.close()

# ---------- Seguridad ----------
def csrf():
    if "csrf" not in session: session["csrf"] = secrets.token_hex(16)
    return session["csrf"]
app.jinja_env.globals["csrf"] = csrf

@app.before_request
def proteger():
    if request.method == "POST" and not secrets.compare_digest(
            request.form.get("csrf", ""), session.get("csrf", "x")):
        abort(400)

@app.after_request
def cabeceras(r):
    r.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'; style-src 'self'",
        "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"})
    return r

def requiere(rol):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if "uid" not in session: return redirect(url_for("login"))
            if session["rol"] != rol: abort(403)
            return f(*a, **k)
        return w
    return deco

# ---------- Rutas ----------
@app.route("/")
def inicio():
    if "uid" not in session: return redirect(url_for("login"))
    return redirect(url_for("estudiante" if session["rol"] == "estudiante" else "profesor"))

@app.route("/salud")
def salud():  # para monitoreo de disponibilidad
    db().execute("SELECT 1"); return {"estado": "ok"}

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u, clave = request.form.get("usuario", "").strip().lower(), request.form.get("clave", "")
        k = (u, request.remote_addr)
        FALLOS[k] = [t for t in FALLOS.get(k, []) if time.time() - t < BLOQUEO]
        if len(FALLOS[k]) >= MAX_FALLOS:
            flash("Demasiados intentos. Espere 5 minutos e intente de nuevo.")
            return render_template("login.html"), 429
        row = db().execute("SELECT * FROM usuarios WHERE usuario=?", (u,)).fetchone()
        if row and check_password_hash(row["clave"], clave):
            FALLOS.pop(k, None); session.clear(); session.permanent = True
            session.update(uid=row["id"], rol=row["rol"], nombre=row["nombre"])
            return redirect(url_for("inicio"))
        FALLOS[k].append(time.time())
        flash("Usuario o contraseña incorrectos.")  # mensaje genérico
    return render_template("login.html")

@app.post("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

@app.route("/estudiante")
@requiere("estudiante")
def estudiante():
    filas = db().execute("""SELECT m.nombre, m.horario, p.nombre AS profesor, i.calificacion
        FROM inscripciones i JOIN materias m ON m.id=i.materia_id JOIN usuarios p ON p.id=m.profesor_id
        WHERE i.estudiante_id=? ORDER BY m.nombre""", (session["uid"],)).fetchall()
    notas = [f["calificacion"] for f in filas if f["calificacion"] is not None]
    return render_template("estudiante.html", filas=filas, promedio=sum(notas)/len(notas) if notas else None)

@app.route("/profesor")
@requiere("profesor")
def profesor():
    ms = db().execute("""SELECT m.id, m.nombre, m.horario, COUNT(i.estudiante_id) AS alumnos
        FROM materias m LEFT JOIN inscripciones i ON i.materia_id=m.id
        WHERE m.profesor_id=? GROUP BY m.id""", (session["uid"],)).fetchall()
    return render_template("profesor.html", materias=ms)

@app.route("/profesor/materia/<int:mid>", methods=["GET", "POST"])
@requiere("profesor")
def materia(mid):
    d = db()
    m = d.execute("SELECT * FROM materias WHERE id=? AND profesor_id=?", (mid, session["uid"])).fetchone()
    if not m: abort(403)  # un profesor solo edita SUS materias
    alumnos = d.execute("""SELECT u.id, u.nombre, u.usuario, i.calificacion FROM inscripciones i
        JOIN usuarios u ON u.id=i.estudiante_id WHERE i.materia_id=? ORDER BY u.nombre""", (mid,)).fetchall()
    if request.method == "POST":
        nuevas = {}
        for a in alumnos:
            v = request.form.get(f"n_{a['id']}", "").strip().replace(",", ".")
            if v == "": nuevas[a["id"]] = None; continue
            try: x = float(v)
            except ValueError: x = -1
            if not 0 <= x <= 10:
                flash(f"Calificación inválida para {a['nombre']}: use un número de 0 a 10."); 
                return render_template("materia.html", m=m, alumnos=alumnos), 400
            nuevas[a["id"]] = round(x, 1)
        for a in alumnos:
            if nuevas[a["id"]] != a["calificacion"]:
                d.execute("UPDATE inscripciones SET calificacion=? WHERE estudiante_id=? AND materia_id=?",
                          (nuevas[a["id"]], a["id"], mid))
                d.execute("INSERT INTO auditoria(profesor_id,estudiante_id,materia_id,anterior,nuevo) VALUES(?,?,?,?,?)",
                          (session["uid"], a["id"], mid, a["calificacion"], nuevas[a["id"]]))
        d.commit(); flash("Calificaciones guardadas correctamente.")
        return redirect(url_for("materia", mid=mid))
    return render_template("materia.html", m=m, alumnos=alumnos)

with app.app_context(): init_db()
if __name__ == "__main__":
    app.run(debug=False)
