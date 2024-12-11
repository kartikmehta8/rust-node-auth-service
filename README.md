# Rust-Node Authentication Service

## Overview
This project is a robust authentication service that integrates a **Rust backend** (compiled as a Node.js native module using Neon bindings) with an **Express.js server**. It uses **MongoDB** for storing user information and **JWT tokens** for secure authentication.

### Key Features
- User Registration with password hashing (using `bcrypt`).
- Secure Login with JWT generation.
- Protected routes using JWT verification middleware.
- MongoDB integration for persistent user data storage.

## Endpoints

### 1. **User Registration**
- **URL**: `/signup`
- **Method**: `POST`
- **Request Body**:
  ```json
  {
    "name": "John Doe",
    "email": "john.doe@example.com",
    "username": "johndoe",
    "password": "securepassword"
  }
  ```
- **Response**:
  - **Success** (201):
    ```json
    {
      "message": "User registered successfully."
    }
    ```
  - **Failure** (400 or 422):
    ```json
    {
      "error": "Validation failed: <details>."
    }
    ```

### 2. **User Login**
- **URL**: `/login`
- **Method**: `POST`
- **Request Body**:
  ```json
  {
    "username": "johndoe",
    "password": "securepassword"
  }
  ```
- **Response**:
  - **Success** (200):
    ```json
    {
      "token": "<jwt-token>"
    }
    ```
  - **Failure** (401):
    ```json
    {
      "error": "Invalid username or password."
    }
    ```

### 3. **Protected Route**
- **URL**: `/protected`
- **Method**: `GET`
- **Headers**:
  ```json
  {
    "Authorization": "Bearer <jwt-token>"
  }
  ```
- **Response**:
  - **Success** (200):
    ```json
    {
      "message": "Access granted."
    }
    ```
  - **Failure** (401):
    ```json
    {
      "error": "Unauthorized."
    }
    ```

## Environment Variables
| Variable       | Description                           | Default Value             |
|----------------|---------------------------------------|---------------------------|
| `MONGO_URI`    | MongoDB connection string            | `mongodb://localhost:27017`|
| `DATABASE_NAME`| Database name for the project        | `auth_service`            |
