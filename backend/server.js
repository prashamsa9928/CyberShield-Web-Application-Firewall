const express = require("express");
const cors = require("cors");
const path = require("path");

const app = express();

// ✅ MIDDLEWARE
app.use(cors({ origin: "*" }));
app.use(express.json());

// ✅ OPTIONAL: serve frontend (safe)
app.use(express.static(path.join(__dirname, "../waf_frontend")));

// ✅ STORAGE
let logs = [];
let attackers = {};

// ✅ RULES (WAF detection)
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

// ✅ WAF CHECK FUNCTION
function checkAttack(input, ip) {
    for (let rule of rules) {
        if (rule.pattern.test(input)) {

            // track attacker
            attackers[ip] = (attackers[ip] || 0) + 1;

            // log attack
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

// ✅ SIMULATE ATTACK (BUTTON)
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

// ✅ FETCH DATA (LOAD ANALYTICS BUTTON)
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

// ✅ ROOT CHECK
app.get("/", (req, res) => {
    res.send("CyberShield Backend Running 🚀");
});

// ✅ PORT FIX (VERY IMPORTANT FOR RENDER)
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log("🔥 Server running on port " + PORT);
});