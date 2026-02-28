/* ==========================================
   AI EMAIL THREAT DETECTOR - FINAL VERSION
========================================== */

document.addEventListener("DOMContentLoaded", () => {

    /* ================= UTIL ================= */

    const Utils = {
        notify(message, type = "info") {
            alert(message); // simple and clean for project
        },
        validateEmail(email) {
            return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
        }
    };

    /* ================= PASSWORD TOGGLE ================= */

    document.querySelectorAll(".toggle-password").forEach(btn => {
        btn.addEventListener("click", () => {
            const input = document.getElementById(btn.dataset.target);
            if (!input) return;

            input.type = input.type === "password" ? "text" : "password";
        });
    });

    /* ================= PASSWORD STRENGTH ================= */

    const passwordInput = document.getElementById("password");
    const strengthBar = document.getElementById("strength-bar");
    const strengthText = document.getElementById("strength-text");

    if (passwordInput && strengthBar) {
        passwordInput.addEventListener("input", () => {
            const value = passwordInput.value;
            let score = 0;

            if (value.length >= 8) score++;
            if (/[A-Z]/.test(value)) score++;
            if (/[a-z]/.test(value)) score++;
            if (/[0-9]/.test(value)) score++;
            if (/[^A-Za-z0-9]/.test(value)) score++;

            const percent = (score / 5) * 100;
            strengthBar.style.width = percent + "%";

            const labels = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"];
            strengthText.innerText = value ? "Strength: " + labels[score - 1] : "";
        });
    }

    /* ================= SIGNUP ================= */

    const signupForm = document.querySelector(".signup-form");

    if (signupForm) {
        signupForm.addEventListener("submit", (e) => {
            e.preventDefault();

            const inputs = signupForm.querySelectorAll("input");
            const fullName = inputs[0].value.trim();
            const username = inputs[1].value.trim();
            const email = inputs[2].value.trim();
            const password = inputs[3].value.trim();
            const confirm = inputs[4].value.trim();

            if (!Utils.validateEmail(email))
                return Utils.notify("Invalid Email");

            if (password !== confirm)
                return Utils.notify("Passwords do not match");

            const user = { fullName, username, email, password };

            localStorage.setItem("user", JSON.stringify(user));

            Utils.notify("Account Created Successfully!");
            window.location.href = "index.html";
        });
    }

    /* ================= LOGIN ================= */

    const loginForm = document.querySelector(".login-form");

    if (loginForm) {
        loginForm.addEventListener("submit", (e) => {
            e.preventDefault();

            const username = loginForm.querySelector("input[type='text']").value.trim();
            const password = loginForm.querySelector("#password").value.trim();

            const savedUser = JSON.parse(localStorage.getItem("user"));

            if (!savedUser)
                return Utils.notify("No account found. Please Sign Up.");

            if (username === savedUser.username && password === savedUser.password) {
                sessionStorage.setItem("loggedIn", "true");
                Utils.notify("Login Successful!");
                window.location.href = "dashboard.html";
            } else {
                Utils.notify("Invalid Username or Password");
            }
        });
    }

    /* ================= FORGET PASSWORD ================= */

    const forgetForm = document.querySelector(".forgetpassword-form");

    if (forgetForm) {
        forgetForm.addEventListener("submit", (e) => {
            e.preventDefault();
            const email = forgetForm.querySelector("input").value;

            if (!Utils.validateEmail(email))
                return Utils.notify("Invalid Email");

            Utils.notify("Reset link sent to your email (Demo)");
        });
    }

    /* ================= DASHBOARD PROTECTION ================= */

    if (window.location.pathname.includes("dashboard.html")) {
        const isLogged = sessionStorage.getItem("loggedIn");
        if (!isLogged) {
            Utils.notify("Please Login First");
            window.location.href = "index.html";
        }
    }

    /* ================= LOGOUT ================= */

    const logoutLink = document.querySelector("#footer a");

    if (logoutLink) {
        logoutLink.addEventListener("click", (e) => {
            e.preventDefault();
            sessionStorage.removeItem("loggedIn");
            Utils.notify("Logged Out Successfully");
            window.location.href = "index.html";
        });
    }

    /* ================= EMAIL ANALYZER ================= */

    const emailForm = document.querySelector("#email-form form");

    if (emailForm) {
        emailForm.addEventListener("submit", (e) => {
            e.preventDefault();

            const subject = emailForm.subject.value.toLowerCase();
            const content = emailForm.content.value.toLowerCase();
            let score = 0;

            const spamWords = ["lottery", "winner", "free", "urgent", "click", "verify"];

            spamWords.forEach(word => {
                if (subject.includes(word) || content.includes(word))
                    score += 15;
            });

            const links = (content.match(/https?:\/\/[^\s]+/g) || []).length;
            if (links > 1) score += links * 5;

            score = Math.min(score, 100);

            let status = "LEGITIMATE";
            let category = "Safe";

            if (score > 70) {
                status = "PHISHING";
                category = "High Risk";
            } else if (score > 40) {
                status = "SUSPICIOUS";
                category = "Medium Risk";
            } else if (score > 20) {
                status = "CAUTION";
                category = "Low Risk";
            }

            document.getElementById("spam-status").innerText = status;
            document.getElementById("risk-score").innerText = score + "%";
            document.getElementById("category").innerText = category;
            document.getElementById("explanation").innerText =
                score > 40
                    ? "This email contains suspicious indicators."
                    : "No major spam patterns detected.";

            saveHistory(subject, score, status);
        });
    }

    /* ================= HISTORY ================= */

    function saveHistory(subject, score, status) {
        let history = JSON.parse(localStorage.getItem("history")) || [];

        history.unshift({
            subject,
            score,
            status,
            time: new Date().toLocaleString()
        });

        history = history.slice(0, 5);
        localStorage.setItem("history", JSON.stringify(history));
        renderHistory();
    }

    function renderHistory() {
        const container = document.getElementById("recent-history");
        if (!container) return;

        const history = JSON.parse(localStorage.getItem("history")) || [];

        if (history.length === 0) {
            container.innerHTML = "<p>No History</p>";
            return;
        }

        container.innerHTML = history.map(item => `
            <div style="border-bottom:1px solid #ccc; padding:8px 0;">
                <strong>${item.subject}</strong><br>
                Status: ${item.status}<br>
                Risk: ${item.score}%<br>
                <small>${item.time}</small>
            </div>
        `).join("");
    }

    renderHistory();
});
// frontend/script.js - Updated with backend API connection

// API Configuration
const API_BASE_URL = 'http://localhost:5000/api';  // Backend URL

// Utility Functions
const showMessage = (message, type = 'info') => {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${type}`;
    messageDiv.textContent = message;
    
    const form = document.querySelector('form');
    if (form) {
        form.insertBefore(messageDiv, form.firstChild);
    }
    
    setTimeout(() => messageDiv.remove(), 5000);
};

// API Request Helper
async function apiRequest(endpoint, method = 'GET', data = null) {
    const url = `${API_BASE_URL}${endpoint}`;
    
    const headers = {
        'Content-Type': 'application/json',
    };
    
    const config = {
        method,
        headers,
        credentials: 'include',  // Important for cookies/sessions
    };
    
    if (data && (method === 'POST' || method === 'PUT')) {
        config.body = JSON.stringify(data);
    }
    
    try {
        const response = await fetch(url, config);
        const responseData = await response.json();
        
        if (!response.ok) {
            throw new Error(responseData.error || 'Request failed');
        }
        
        return responseData;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}
