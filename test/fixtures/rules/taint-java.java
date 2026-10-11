// Fixture for rules/semgrep/taint-java.yaml (servlets and Spring MVC). Written for the Hullproof Engine.
// Each "ruleid" line must match and each "ok" line must not, checked by semgrep --test in test/rules.test.ts.
import java.io.*;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.*;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.io.FilenameUtils;
import org.owasp.encoder.Encode;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

public class TaintFixtures extends HttpServlet {
  private Connection connection;
  private JdbcTemplate jdbcTemplate;
  private RestTemplate restTemplate;

  // ---- SQL injection, CWE-89 ----

  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String name = request.getParameter("name");
    Statement statement = connection.createStatement();
    // ruleid: hullproof-taint-java-sql-injection
    ResultSet rs = statement.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    // ok: hullproof-taint-java-sql-injection
    PreparedStatement ps = connection.prepareStatement("SELECT * FROM users WHERE name = ?");
    ps.setString(1, name);
    // ok: hullproof-taint-java-sql-injection
    statement.executeQuery("SELECT * FROM users WHERE id = " + Integer.parseInt(request.getParameter("id")));

    // ---- XSS, CWE-79 ----
    // ruleid: hullproof-taint-java-xss
    response.getWriter().println("<p>Hello " + name + "</p>");
    // ok: hullproof-taint-java-xss
    response.getWriter().println("<p>Hello " + Encode.forHtml(name) + "</p>");
    PrintWriter out = response.getWriter();
    // ruleid: hullproof-taint-java-xss
    out.format("<b>%s</b>", request.getHeader("Referer"));
    // ok: hullproof-taint-java-xss
    out.println("<p>static</p>");
  }

  @GetMapping("/users")
  public String users(@RequestParam("q") String q, @PathVariable String org) {
    // ruleid: hullproof-taint-java-sql-injection
    jdbcTemplate.queryForList("SELECT * FROM users WHERE org = '" + org + "'");
    // ok: hullproof-taint-java-sql-injection
    jdbcTemplate.queryForList("SELECT * FROM users WHERE org = ?", org);
    // ruleid: hullproof-taint-java-sql-injection
    entityManager.createQuery("FROM User u WHERE u.name = '" + q + "'");
    return "users";
  }

  public void notAHandler(String q) throws Exception {
    // ok: hullproof-taint-java-sql-injection
    connection.createStatement().executeQuery("SELECT * FROM t WHERE x = '" + q + "'");
  }

  // ---- Command injection, CWE-78 ----

  @PostMapping("/ping")
  public String ping(@RequestParam String host) throws Exception {
    // ruleid: hullproof-taint-java-command-injection
    Runtime.getRuntime().exec("ping -c 1 " + host);
    // ruleid: hullproof-taint-java-command-injection
    new ProcessBuilder("sh", "-c", "ping " + host).start();
    // ok: hullproof-taint-java-command-injection
    new ProcessBuilder("ping", "-c", "1", "localhost").start();
    // ok: hullproof-taint-java-command-injection
    Runtime.getRuntime().exec("uptime");
    return "ok";
  }

  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    String[] cmd = {"/bin/sh", "-c", "ls " + req.getParameter("dir")};
    // ruleid: hullproof-taint-java-command-injection
    Runtime.getRuntime().exec(cmd);

    // ---- Path traversal, CWE-22 ----
    String file = req.getParameter("file");
    // ruleid: hullproof-taint-java-path-traversal
    FileInputStream in = new FileInputStream("/srv/files/" + file);
    // ruleid: hullproof-taint-java-path-traversal
    byte[] data = Files.readAllBytes(Paths.get("/srv/files", file));
    // ok: hullproof-taint-java-path-traversal
    FileInputStream in2 = new FileInputStream(new File("/srv/files", FilenameUtils.getName(file)));
    // ok: hullproof-taint-java-path-traversal
    FileInputStream in3 = new FileInputStream("/srv/files/readme.txt");
  }

  @GetMapping("/download/{name}")
  public byte[] download(@PathVariable("name") String name) throws Exception {
    checkFileNameAllowed(name);
    // ok: hullproof-taint-java-path-traversal
    File target = new File("/srv/files", name);
    return Files.readAllBytes(target.toPath());
  }

  // ---- SSRF, CWE-918 ----

  @GetMapping("/fetch")
  public String fetch(@RequestParam String url) throws Exception {
    // ruleid: hullproof-taint-java-ssrf
    InputStream s = new URL(url).openStream();
    // ruleid: hullproof-taint-java-ssrf
    String body = restTemplate.getForObject(url, String.class);
    // ok: hullproof-taint-java-ssrf
    String q = restTemplate.getForObject("https://api.example.com/search?q=" + url, String.class);
    // ok: hullproof-taint-java-ssrf
    String h = restTemplate.getForObject("https://status.example.com/health", String.class);
    return body + q + h;
  }

  @GetMapping("/fetch2")
  public String fetch2(@RequestParam String url) throws Exception {
    validateOutboundUrl(url);
    // ok: hullproof-taint-java-ssrf
    return restTemplate.getForObject(url, String.class);
  }
}
