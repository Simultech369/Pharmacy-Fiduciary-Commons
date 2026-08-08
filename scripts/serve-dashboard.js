const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");

const PORT = 8080;
const DIST_DIR = path.resolve(__dirname, "..", "dist", "dashboard");

const MIME_TYPES = {
  ".html": "text/html",
  ".css": "text/css",
  ".js": "application/javascript",
  ".json": "application/json",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".md": "text/markdown"
};

const { execFile } = require("node:child_process");

function pythonCommand() {
  if (process.env.PYTHON) {
    return process.env.PYTHON;
  }
  return process.platform === "win32" ? "python" : "python3";
}

const server = http.createServer((req, res) => {
  const reqUrl = new URL(req.url, `http://localhost:${PORT}`);
  
  if (reqUrl.pathname === "/api/rag") {
    const q = reqUrl.searchParams.get("q") || "solvency";
    const scriptPath = path.resolve(__dirname, "dossier_rag_retrieval.py");
    const pythonExe = pythonCommand();
      
    execFile(pythonExe, [scriptPath, "--query", q, "--json"], { encoding: "utf8" }, (err, stdout) => {
      res.writeHead(200, { 
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
      });
      if (err) {
        return res.end(JSON.stringify({ error: err.message, raw: stdout || "" }));
      }
      try {
        return res.end(JSON.stringify(JSON.parse(stdout)));
      } catch (parseErr) {
        return res.end(JSON.stringify({ query: q, error: parseErr.message, raw: stdout || "" }));
      }
    });
    return;
  }

  let filePath = path.join(DIST_DIR, req.url === "/" ? "index.html" : req.url);
  
  if (!filePath.startsWith(DIST_DIR)) {
    res.writeHead(403);
    return res.end("Forbidden");
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      return res.end("404 Not Found");
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || "application/octet-stream";

    res.writeHead(200, { "Content-Type": contentType });
    fs.createReadStream(filePath).pipe(res);
  });
});

server.listen(PORT, () => {
  console.log(`\n==================================================`);
  console.log(`🚀 Dashboard live at: http://localhost:${PORT}`);
  console.log(`==================================================\n`);
});
