const express = require("express");
const bodyParser = require("body-parser");
const {
  register_user,
  login_user,
  verify_token,
} = require("./index.node"); // Import Rust bindings.

const app = express();
const PORT = 5000;

// Middleware for parsing JSON bodies.
app.use(bodyParser.json());

// Utility function for sending consistent error responses.
const handleError = (res, message, status = 400) => {
  res.status(status).json({ error: message });
};

// Sign-up endpoint.
app.post("/signup", (req, res) => {
  const { name, email, username, password } = req.body;

  // Basic validation.
  if (!name || !email || !username || !password) {
    return handleError(res, "All fields (name, email, username, password) are required.", 422);
  }

  try {
    const success = register_user(name, email, username, password);

    if (success) {
      res.status(201).json({ message: "User registered successfully." });
    } else {
      handleError(res, "Failed to register user. Please try again.");
    }
  } catch (err) {
    console.error("Error during registration:", err);
    handleError(res, "An internal error occurred.", 500);
  }
});

// Login endpoint.
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // Basic validation.
  if (!username || !password) {
    return handleError(res, "Username and password are required.", 422);
  }

  try {
    const token = login_user(username, password);
    res.status(200).json({ token });
  } catch (err) {
    console.error("Login error:", err);
    handleError(res, "Invalid username or password.", 401);
  }
});

// Middleware to validate JWT for protected routes.
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return handleError(res, "Authorization header missing or invalid.", 401);
  }

  const token = authHeader.split(" ")[1];
  try {
    if (!verify_token(token)) {
      return handleError(res, "Invalid or expired token.", 401);
    }
    next();
  } catch (err) {
    console.error("Token verification error:", err);
    handleError(res, "Unauthorized access.", 401);
  }
};

// Protected route example.
app.get("/protected", authenticate, (req, res) => {
  res.status(200).json({ message: "Access granted." });
});

// Global error handling middleware.
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  handleError(res, "An internal server error occurred.", 500);
});

// Start the server.
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
