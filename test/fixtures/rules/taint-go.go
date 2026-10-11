// Fixture for rules/semgrep/taint-go.yaml (net/http, gorilla/mux and Gin). Written for the Hullproof Engine.
// Each "ruleid" line must match and each "ok" line must not, checked by semgrep --test in test/rules.test.ts.
package fixtures

import (
	"database/sql"
	"fmt"
	"html"
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/mux"
)

var db *sql.DB

// ---- SQL injection, CWE-89 ----

func userHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ruleid: hullproof-taint-go-sql-injection
	rows, _ := db.Query("SELECT * FROM users WHERE name = '" + name + "'")
	// ruleid: hullproof-taint-go-sql-injection
	db.Exec(fmt.Sprintf("DELETE FROM users WHERE name = '%s'", r.FormValue("victim")))
	// ok: hullproof-taint-go-sql-injection
	rows2, _ := db.Query("SELECT * FROM users WHERE name = $1", name)
	id, _ := strconv.Atoi(r.FormValue("id"))
	// ok: hullproof-taint-go-sql-injection
	rows3, _ := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %d", id))
	_, _, _ = rows, rows2, rows3
}

func ginOrders(c *gin.Context) {
	status := c.Query("status")
	// ruleid: hullproof-taint-go-sql-injection
	db.QueryContext(c, "SELECT * FROM orders WHERE status = '"+status+"'")
	// ok: hullproof-taint-go-sql-injection
	db.QueryContext(c, "SELECT * FROM orders WHERE status = $1", status)
}

func notAHandler(name string) {
	// ok: hullproof-taint-go-sql-injection
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}

// ---- XSS, CWE-79 ----

func helloHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ruleid: hullproof-taint-go-xss
	fmt.Fprintf(w, "<p>Hello %s</p>", name)
	// ok: hullproof-taint-go-xss
	fmt.Fprintf(w, "<p>Hello %s</p>", html.EscapeString(name))
	// ruleid: hullproof-taint-go-xss
	w.Write([]byte("<b>" + r.FormValue("msg") + "</b>"))
	// ok: hullproof-taint-go-xss
	w.Write([]byte("<b>static</b>"))
	// ruleid: hullproof-taint-go-xss
	_ = template.HTML(r.FormValue("bio"))
}

// ---- Command injection, CWE-78 ----

func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	// ruleid: hullproof-taint-go-command-injection
	exec.Command("sh", "-c", "ping -c 1 "+host).Run()
	// ruleid: hullproof-taint-go-command-injection
	exec.Command(r.FormValue("tool"), "--version").Run()
	// ok: hullproof-taint-go-command-injection
	exec.Command("ping", "-c", "1", host).Run()
	// ok: hullproof-taint-go-command-injection
	exec.Command("uptime").Run()
}

// ---- Path traversal, CWE-22 ----

func fileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	// ruleid: hullproof-taint-go-path-traversal
	data, _ := os.ReadFile(filepath.Join("/srv/files", vars["name"]))
	// ok: hullproof-taint-go-path-traversal
	safe, _ := os.ReadFile(filepath.Join("/srv/files", filepath.Base(vars["name"])))
	// ruleid: hullproof-taint-go-path-traversal
	http.ServeFile(w, r, "/srv/files/"+r.URL.Query().Get("f"))
	_, _ = data, safe
}

func ginDownload(c *gin.Context) {
	p := filepath.Join("/srv/files", c.Param("name"))
	checkInsideRoot(p)
	// ok: hullproof-taint-go-path-traversal
	c.File(p)
}

// ---- SSRF, CWE-918 ----

func fetchHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	// ruleid: hullproof-taint-go-ssrf
	resp, _ := http.Get(target)
	// ok: hullproof-taint-go-ssrf
	resp2, _ := http.Get("https://api.example.com/search?q=" + target)
	// ok: hullproof-taint-go-ssrf
	resp3, _ := http.Get(fmt.Sprintf("https://api.example.com/items/%s", target))
	// ok: hullproof-taint-go-ssrf
	resp4, _ := http.Get("https://status.example.com/health")
	_, _, _, _ = resp, resp2, resp3, resp4
}

func ginHook(c *gin.Context) {
	cb := c.PostForm("callback")
	// ruleid: hullproof-taint-go-ssrf
	req, _ := http.NewRequest("POST", cb, nil)
	_ = req
}
