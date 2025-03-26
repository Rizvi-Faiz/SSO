const express = require("express");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: ["http://localhost:3001", "http://localhost:3000"],
    credentials: true,
  })
);

const users = [{ id: 1, email: "test@example.com", password: "1234" }];
const SECRET = "super_secret_key";

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const user = users.find((u) => u.email === email && u.password === password);

  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const token = jwt.sign({ id: user.id, email: user.email }, SECRET, {
    expiresIn: "7d",
  });

  res.cookie("sso_token", token, {
    httpOnly: false,
    secure: process.env.NODE_ENV === "production", 
    sameSite: "lax", 
    path: "/", 
  });

  res.json({ message: "Login successful", token });
});

app.get("/verify", (req, res) => {
  const token = req.cookies.sso_token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const user = jwt.verify(token, SECRET);
    res.json({ user });
  } catch (error) {
    res.clearCookie("sso_token", {
      httpOnly: false,
      secure: process.env.NODE_ENV === "production",
      path: "/",
    });
    res.status(401).json({ error: "Invalid token" });
  }
});

app.post("/logout", (req, res) => {
  // Clear the cookie on logout
  res.clearCookie("sso_token", {
    httpOnly: false,
    secure: process.env.NODE_ENV === "production",
    path: "/",
  });
  res.json({ message: "Logged out successfully" });
});

app.listen(4000, () => console.log("✅ SSO Auth Server running on port 4000"));