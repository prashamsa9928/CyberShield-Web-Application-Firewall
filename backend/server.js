const express = require("express");
const cors = require("cors");
const path = require("path");

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "../waf_frontend")));

// storage
let logs = [];
let attackers = {};

// rules
const rules = [
    {
        name: "SQL Injection",
        pattern: /(SELECT|DROP|INSERT|DELETE|--)/i,
        severity: "HIGH"
    },
    {
        name: "XSS Attack",
        pattern: /(<script>|javascript:)/i,
        severity: "HIGH"
    }
];

// WAF middleware
app.use((req, res, next) => {

    const data = JSON.stringify(req.body) + req.url;

    for (let rule of rules) {
        if (rule.pattern.test(data)) {

            const ip = req.ip;

            attackers[ip] = (attackers[ip] || 0) + 1;

            logs.push({
                ip: ip,
                attack: rule.name,
                severity: rule.severity,
                time: new Date().toLocaleString()
            });

            return res.status(403).json({
                message: "Blocked by WAF",
                attack: rule.name
            });
        }
    }

    next();
});

// test route
app.post("/api", (req, res) => {
    res.json({ message: "Request allowed ✅" });
});

app.get("/", (req, res) => {
    res.send("CyberShield Backend Running 🚀");
});

// analytics route
app.get("/analytics", (req, res) => {

    const high = logs.filter(l => l.severity === "HIGH").length;

    res.json({
        totalAttacks: logs.length,
        highSeverity: high,
        mediumSeverity: 0,
        logs: logs,
        attackers: attackers
    });
});

// start server
app.listen(3000, () => {
    console.log("🔥 Server running at http://localhost:3000");
});