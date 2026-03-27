const express = require("express");
const cors = require("cors");
const path = require("path");

const app = express();

// ✅ MIDDLEWARE
app.use(cors({ origin: "*" }));
app.use(express.json());

// ✅ OPTIONAL: serve frontend
app.use(express.static(path.join(__dirname, "../waf_frontend")));

// ✅ STORAGE
let logs = [];
let attackers = {};

// ✅ RULES
const rules = [
    {
        name: "SQL Injection",
        pattern: /(SELECT|DROP|INSERT|DELETE|UPDATE|--)/i,
        severity: "HIGH"
    },
    {
        name: "XSS Attack",
        pattern: /(<script>|javascript:)/i,
        severity: "HIGH"
    }
];

// ✅ WAF FUNCTION
function checkAttack(input, ip) {
    for (let rule of rules) {
        if (rule.pattern.test(input)) {

            attackers[ip] = (attackers[ip] || 0) + 1;

            logs.push({
                ip: ip,
                attack: rule.name,
                severity: rule.severity,
                input: input,
                time: new Date().toLocaleString()
            });

            return {
                detected: true,
                type: rule.name
            };
        }
    }

    return { detected: false };
}

// ✅ SIMULATE ATTACK
app.post("/analytics", (req, res) => {
    const input = req.body.input || "";
    const ip = req.ip;

    const result = checkAttack(input, ip);

    if (result.detected) {
        return res.json({
            message: "🚨 Attack Detected",
            type: result.type
        });
    }

    res.json({ message: "✅ Safe Request" });
});

// ✅ GET DATA (VERY IMPORTANT)
app.get("/api", (req, res) => {
    const high = logs.filter(l => l.severity === "HIGH").length;

    res.json({
        totalAttacks: logs.length,
        highSeverity: high,
        mediumSeverity: 0,
        logs: logs,
        attackers: attackers
    });
});

// ✅ RESET (FOR DEMO)
app.get("/reset", (req, res) => {
    logs = [];
    attackers = {};
    res.send("Reset done");
});

// ✅ ROOT
app.get("/", (req, res) => {
    res.send("CyberShield Backend Running 🚀");
});

// ✅ PORT FIX
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log("🔥 Server running on port " + PORT);
});