<?php
// Fixture for rules/semgrep/taint-php.yaml (plain PHP and Laravel). Written for the Hullproof Engine.
// Each "ruleid" line must match and each "ok" line must not, checked by semgrep --test in test/rules.test.ts.

// ---- SQL injection, CWE-89 ----

function plain_user($conn, $pdo) {
    $name = $_GET['name'];
    // ruleid: hullproof-taint-php-sql-injection
    $r = mysqli_query($conn, "SELECT * FROM users WHERE name = '" . $name . "'");
    // ruleid: hullproof-taint-php-sql-injection
    $r = $pdo->query("SELECT * FROM users WHERE name = '$name'");
    // ok: hullproof-taint-php-sql-injection
    $st = $pdo->prepare("SELECT * FROM users WHERE name = ?");
    $st->execute([$name]);
    // ok: hullproof-taint-php-sql-injection
    $r = $pdo->query("SELECT * FROM users WHERE id = " . intval($_GET['id']));
    return $r;
}

class UserController {
    public function search(Request $request) {
        $q = $request->input('q');
        // ruleid: hullproof-taint-php-sql-injection
        $rows = DB::select("SELECT * FROM users WHERE name LIKE '%" . $q . "%'");
        // ok: hullproof-taint-php-sql-injection
        $rows = DB::select("SELECT * FROM users WHERE name LIKE ?", ['%' . $q . '%']);
        // ok: hullproof-taint-php-sql-injection
        $me = DB::select("SELECT * FROM users WHERE id = " . $request->user()->id);
        return $rows;
    }
}

function fixed_query($pdo, $value) {
    // ok: hullproof-taint-php-sql-injection
    return $pdo->query("SELECT * FROM t WHERE x = '" . $value . "'");
}

// ---- XSS, CWE-79 ----

function greet() {
    // ruleid: hullproof-taint-php-xss
    echo "<p>Hello " . $_GET['name'] . "</p>";
    // ok: hullproof-taint-php-xss
    echo "<p>Hello " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') . "</p>";
    // ok: hullproof-taint-php-xss
    echo "<p>Hello world</p>";
    $msg = $_POST['msg'];
    // ruleid: hullproof-taint-php-xss
    print($msg);
    // ok: hullproof-taint-php-xss
    echo json_encode(['msg' => $msg]);
}

// ---- Command injection, CWE-78 ----

function ping() {
    $host = $_GET['host'];
    // ruleid: hullproof-taint-php-command-injection
    system("ping -c 1 " . $host);
    // ruleid: hullproof-taint-php-command-injection
    $out = shell_exec("nslookup " . $_POST['domain']);
    // ok: hullproof-taint-php-command-injection
    system("ping -c 1 " . escapeshellarg($host));
    // ok: hullproof-taint-php-command-injection
    exec("uptime");
    return $out;
}

// ---- Path traversal, CWE-22 ----

function show_page() {
    $page = $_GET['page'];
    // ruleid: hullproof-taint-php-path-traversal
    include "pages/" . $page . ".php";
    // ruleid: hullproof-taint-php-path-traversal
    $text = file_get_contents("/srv/docs/" . $page);
    // ok: hullproof-taint-php-path-traversal
    $text = file_get_contents("/srv/docs/" . basename($page));
    // ok: hullproof-taint-php-path-traversal
    $text = file_get_contents("/srv/docs/index.txt");
    return $text;
}

function delete_upload() {
    $file = $_POST['file'];
    checkPathInsideUploads($file);
    // ok: hullproof-taint-php-path-traversal
    unlink("/srv/uploads/" . $file);
}

// ---- SSRF, CWE-918 ----

function fetch_url() {
    $url = $_GET['url'];
    // ruleid: hullproof-taint-php-ssrf
    $ch = curl_init($url);
    // ok: hullproof-taint-php-ssrf
    $ch2 = curl_init("https://api.example.com/search?q=" . $url);
    // ok: hullproof-taint-php-ssrf
    $ch3 = curl_init("https://status.example.com/health");
    return [$ch, $ch2, $ch3];
}

class HookController {
    public function test(Request $request) {
        $target = $request->input('callback');
        // ruleid: hullproof-taint-php-ssrf
        return Http::post($target, ['ping' => true]);
    }

    public function test2(Request $request) {
        $target = $request->input('callback');
        validateOutboundUrl($target);
        // ok: hullproof-taint-php-ssrf
        return Http::post($target, ['ping' => true]);
    }
}
