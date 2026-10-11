const origin = req.headers.get("origin");
res.headers.set("Access-Control-Allow-Origin", origin);
