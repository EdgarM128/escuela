"""Pruebas automáticas: evidencia de los atributos de calidad."""
import os, re, tempfile, time, unittest
os.environ["DATABASE"] = os.path.join(tempfile.mkdtemp(), "t.db")
import app as A

def tok(c, url="/login"):
    return re.search(r'name="csrf" value="(\w+)"', c.get(url).get_data(as_text=True)).group(1)
def entrar(c, u, p="Demo2026!"):
    return c.post("/login", data={"usuario": u, "clave": p, "csrf": tok(c)})

class T(unittest.TestCase):
    def setUp(self): A.FALLOS.clear(); self.c = A.app.test_client()
    def test_01_sin_sesion_redirige(self):
        self.assertEqual(self.c.get("/estudiante").status_code, 302)
    def test_02_estudiante_no_entra_a_profesor(self):
        entrar(self.c, "a1001"); self.assertEqual(self.c.get("/profesor/materia/1").status_code, 403)
    def test_03_estudiante_ve_solo_lo_suyo(self):
        entrar(self.c, "a1001"); h = self.c.get("/estudiante").get_data(as_text=True)
        self.assertIn("Ana Torres", h); self.assertNotIn("Luis Pérez", h)
    def test_04_profesor_no_edita_materia_ajena(self):
        entrar(self.c, "prof.garcia"); self.assertEqual(self.c.get("/profesor/materia/3").status_code, 403)
    def test_05_rechaza_nota_invalida(self):
        entrar(self.c, "prof.garcia"); r = self.c.post("/profesor/materia/1", data={"n_3": "11", "csrf": tok(self.c, "/profesor/materia/1")})
        self.assertEqual(r.status_code, 400)
    def test_06_guarda_nota_y_audita(self):
        entrar(self.c, "prof.garcia"); t = tok(self.c, "/profesor/materia/1")
        self.c.post("/profesor/materia/1", data={"n_3": "9.5", "n_4": "7", "n_6": "6.5", "csrf": t})
        with A.app.app_context():
            self.assertEqual(A.db().execute("SELECT nuevo FROM auditoria WHERE estudiante_id=3").fetchone()[0], 9.5)
    def test_07_csrf_obligatorio(self):
        entrar(self.c, "prof.garcia"); self.assertEqual(self.c.post("/profesor/materia/1", data={"n_3": "1"}).status_code, 400)
    def test_08_bloqueo_por_intentos(self):
        for _ in range(5): entrar(self.c, "a1002", "mala")
        self.assertEqual(entrar(self.c, "a1002").status_code, 429)
    def test_09_clave_hasheada(self):
        with A.app.app_context():
            self.assertTrue(A.db().execute("SELECT clave FROM usuarios").fetchone()[0].startswith(("scrypt", "pbkdf2")))
    def test_10_cabeceras_y_salud(self):
        r = self.c.get("/salud"); self.assertEqual(r.json["estado"], "ok"); self.assertIn("Content-Security-Policy", r.headers)
    def test_11_rendimiento(self):
        entrar(self.c, "a1001"); t = time.perf_counter()
        for _ in range(50): self.c.get("/estudiante")
        ms = (time.perf_counter() - t) / 50 * 1000; print(f"\nTiempo medio /estudiante: {ms:.1f} ms"); self.assertLess(ms, 100)
if __name__ == "__main__": unittest.main(verbosity=2)
