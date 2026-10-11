const allowed = ["https://app.example.com"];
if (allowed.includes(origin)) res.headers.set("Access-Control-Allow-Origin", "https://app.example.com");
