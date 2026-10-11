# Fixture for rules/semgrep/taint-python.yaml. Written for the Hullproof Engine. Each "ruleid" line must match and each
# "ok" line must not, checked by semgrep --test in test/rules.test.ts.
import os
import shlex
import sqlite3
import subprocess
import html
import requests
import urllib.request
from flask import Flask, request, make_response, render_template, jsonify, send_file
from werkzeug.utils import secure_filename
from django.http import HttpResponse
from django.utils.safestring import mark_safe
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from sqlalchemy import text

app = Flask(__name__)
api = FastAPI()
db = sqlite3.connect("app.db")


# ---- SQL injection, CWE-89 ----

@app.route("/user")
def flask_user():
    name = request.args.get("name")
    cur = db.cursor()
    # ruleid: hullproof-taint-py-sql-injection
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    # ruleid: hullproof-taint-py-sql-injection
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    # ok: hullproof-taint-py-sql-injection
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    # ok: hullproof-taint-py-sql-injection
    cur.execute("SELECT * FROM users WHERE id = %d" % int(request.args["id"]))
    return jsonify(cur.fetchall())


def django_search(request):
    q = request.GET["q"]
    # ruleid: hullproof-taint-py-sql-injection
    rows = User.objects.raw("SELECT * FROM app_user WHERE name LIKE '%" + q + "%'")
    # ok: hullproof-taint-py-sql-injection
    rows = User.objects.raw("SELECT * FROM app_user WHERE name = %s", [q])
    return HttpResponse(len(list(rows)))


@api.get("/items")
async def fastapi_items(category: str, session=None):
    # ruleid: hullproof-taint-py-sql-injection
    session.execute(text("SELECT * FROM items WHERE category = '" + category + "'"))
    # ok: hullproof-taint-py-sql-injection
    session.execute(text("SELECT * FROM items WHERE category = :c"), {"c": category})
    return {"ok": True}


def not_a_route(name):
    cur = db.cursor()
    # ok: hullproof-taint-py-sql-injection
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")


# ---- XSS, CWE-79 ----

@app.route("/hello")
def flask_hello():
    name = request.args.get("name", "")
    # ruleid: hullproof-taint-py-xss
    return "<p>Hello " + name + "</p>"


@app.route("/hello2")
def flask_hello2():
    name = request.form["name"]
    # ok: hullproof-taint-py-xss
    return "<p>Hello " + html.escape(name) + "</p>"


@app.route("/hello3")
def flask_hello3():
    name = request.args.get("name")
    # ok: hullproof-taint-py-xss
    return render_template("hello.html", name=name)


@app.route("/hello4")
def flask_hello4():
    name = request.args.get("name")
    # ok: hullproof-taint-py-xss
    return {"name": name}


@app.route("/hello5")
def flask_hello5():
    name = request.cookies.get("name")
    # ruleid: hullproof-taint-py-xss
    resp = make_response("<b>" + name + "</b>")
    # ruleid: hullproof-taint-py-xss
    return resp


def django_hello(request):
    # ruleid: hullproof-taint-py-xss
    return HttpResponse("Hi " + request.GET.get("who"))


def django_hello_safe(request):
    # ok: hullproof-taint-py-xss
    return HttpResponse("Hi " + html.escape(request.GET.get("who")))


def django_mark(request):
    # ruleid: hullproof-taint-py-xss
    return mark_safe(request.POST["bio"])


@api.get("/page")
def fastapi_page(title: str):
    # ruleid: hullproof-taint-py-xss
    return HTMLResponse("<h1>" + title + "</h1>")


@api.get("/json")
def fastapi_json(title: str):
    # ok: hullproof-taint-py-xss
    return {"title": title}


# ---- Command injection, CWE-78 ----

@app.route("/ping")
def flask_ping():
    host = request.args.get("host")
    # ruleid: hullproof-taint-py-command-injection
    os.system("ping -c 1 " + host)
    # ruleid: hullproof-taint-py-command-injection
    subprocess.run("ping -c 1 " + host, shell=True)
    # ruleid: hullproof-taint-py-command-injection
    subprocess.check_output(["sh", "-c", "ping " + host])
    # ok: hullproof-taint-py-command-injection
    subprocess.run("ping -c 1 " + shlex.quote(host), shell=True)
    # ok: hullproof-taint-py-command-injection
    subprocess.run(["ping", "-c", "1", host])
    # ok: hullproof-taint-py-command-injection
    os.system("uptime")
    return "done"


def django_tool(request):
    tool = request.POST["tool"]
    # ruleid: hullproof-taint-py-command-injection
    subprocess.Popen([tool, "--version"])
    return HttpResponse("ok")


@api.post("/convert")
def fastapi_convert(fmt: str):
    # ruleid: hullproof-taint-py-command-injection
    out = subprocess.getoutput("convert in.png out." + fmt)
    return {"out": out}


# ---- Path traversal, CWE-22 ----

@app.route("/file")
def flask_file():
    name = request.args.get("name")
    # ruleid: hullproof-taint-py-path-traversal
    with open(os.path.join("/srv/files", name)) as f:
        data = f.read()
    # ok: hullproof-taint-py-path-traversal
    with open(os.path.join("/srv/files", secure_filename(name))) as f:
        data = f.read()
    # ok: hullproof-taint-py-path-traversal
    with open(os.path.join("/srv/files", os.path.basename(name))) as f:
        data = f.read()
    return jsonify(len(data))


@app.route("/download")
def flask_download():
    path = request.args["path"]
    # ruleid: hullproof-taint-py-path-traversal
    return send_file("/srv/files/" + path)


@app.route("/download2")
def flask_download2():
    path = request.args["path"]
    check_path_inside_root(path)
    # ok: hullproof-taint-py-path-traversal
    return send_file("/srv/files/" + path)


def django_delete(request):
    # ruleid: hullproof-taint-py-path-traversal
    os.remove("/srv/uploads/" + request.POST["file"])
    return HttpResponse("deleted")


@api.get("/read")
def fastapi_read(name: str):
    # ruleid: hullproof-taint-py-path-traversal
    return {"text": open("/srv/notes/" + name).read()}


def fixed_file():
    # ok: hullproof-taint-py-path-traversal
    return open("/srv/notes/readme.txt").read()


# ---- SSRF, CWE-918 ----

@app.route("/fetch")
def flask_fetch():
    url = request.args.get("url")
    # ruleid: hullproof-taint-py-ssrf
    r = requests.get(url, timeout=5)
    # ok: hullproof-taint-py-ssrf
    r = requests.get("https://api.example.com/search?q=" + url, timeout=5)
    # ok: hullproof-taint-py-ssrf
    r = requests.get(f"https://api.example.com/items/{url}", timeout=5)
    return jsonify(r.status_code)


@app.route("/fetch2")
def flask_fetch2():
    url = request.args.get("url")
    if is_safe_url(url):
        # ok: hullproof-taint-py-ssrf
        return jsonify(requests.get(url).status_code)
    return jsonify(400)


def django_proxy(request):
    target = request.GET["target"]
    # ruleid: hullproof-taint-py-ssrf
    body = urllib.request.urlopen(target).read()
    return HttpResponse(len(body))


@api.post("/webhook-test")
async def fastapi_hook(callback: str):
    # ruleid: hullproof-taint-py-ssrf
    requests.post(callback, json={"ping": True})
    return {"ok": True}


def internal_job():
    # ok: hullproof-taint-py-ssrf
    requests.get("https://status.example.com/health")
