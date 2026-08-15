# Auth Microservice

> A modern authentication microservice built with **ASP.NET Core 8**, featuring JWT authentication, refresh token rotation, Google OAuth2, PostgreSQL, Docker, automated tests, and CI validation.

![CI](https://github.com/jospindev-stack/auth-microservice/actions/workflows/ci.yml/badge.svg)
![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet)
![ASP.NET Core](https://img.shields.io/badge/ASP.NET%20Core-8.0-512BD4?logo=dotnet)
![Entity Framework Core](https://img.shields.io/badge/EF%20Core-8.0-68217A)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?logo=postgresql)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)
![JWT](https://img.shields.io/badge/JWT-HS256-orange)
![License](https://img.shields.io/badge/License-MIT-green)

---

# Why this project?

This project demonstrates how to build a secure and scalable authentication service using **ASP.NET Core 8** following modern backend development practices.

It includes:

- JWT Authentication
- Refresh Token Rotation
- Refresh Token Reuse Detection
- Google OAuth2 Login
- PostgreSQL with Entity Framework Core
- Docker & Docker Compose
- Rate Limiting
- Structured Logging (Serilog)
- Health Checks
- Automatic EF Core Migrations
- Automated xUnit Tests
- GitHub Actions CI

---

# Technology Stack

| Category         | Technologies            |
| ---------------- | ----------------------- |
| Backend          | ASP.NET Core 8          |
| ORM              | Entity Framework Core 8 |
| Database         | PostgreSQL 16           |
| Authentication   | JWT + Refresh Tokens    |
| OAuth            | Google OAuth2           |
| Password Hashing | BCrypt.Net              |
| Logging          | Serilog                 |
| Documentation    | Swagger / OpenAPI       |
| Containerization | Docker & Docker Compose |
| Testing          | xUnit + SQLite In-Memory |
| CI               | GitHub Actions          |

---

# Features

| Feature               | Description                                            |
| --------------------- | ------------------------------------------------------ |
| Register              | Email/password registration                            |
| Login                 | JWT authentication                                     |
| Access Token          | HS256 JWT (15 min)                                     |
| Refresh Token         | 7-day opaque refresh token                             |
| Refresh Rotation      | New refresh token on every refresh                     |
| Token Reuse Detection | Detects stolen refresh tokens and revokes all sessions |
| Google OAuth2         | Login with Google account                              |
| Rate Limiting         | Fixed-window limiter on authentication endpoints       |
| Swagger               | Interactive OpenAPI documentation                      |
| Structured Logs       | Console + daily rolling log files                      |
| Health Checks         | Database connectivity verification                     |
| Automatic Migration   | EF Core migrations executed on startup                 |
| Automated Tests       | Authentication and refresh-token scenarios with xUnit |
| Continuous Integration | Restore, build and test on GitHub Actions             |

---

# Project Structure

```text
auth-microservice/
|
|-- .github/
|   `-- workflows/
|       `-- ci.yml
|-- AuthMicroservice/
|   |-- Controllers/
|   |-- Data/
|   |-- DTOs/
|   |-- Entities/
|   |-- Extensions/
|   |-- Migrations/
|   |-- Services/
|   |   |-- Interfaces/
|   |   |-- AuthService.cs
|   |   `-- TokenService.cs
|   |-- Program.cs
|   `-- appsettings.json
|-- AuthMicroservice.Tests/
|   |-- AuthMicroservice.Tests.csproj
|   `-- AuthServiceTests.cs
|-- AuthMicroservice.sln
|-- Dockerfile
|-- docker-compose.yml
|-- .dockerignore
|-- .env.example
`-- README.md
```

---

# Architecture

```text
Client
   |
   v
Controllers
   |
   v
Services
   |
   v
Entity Framework Core
   |
   v
PostgreSQL
```

---

# Prerequisites

- .NET 8 SDK
- Docker Desktop

or

- PostgreSQL 16

---

# Quick Start (Docker)

## Clone

```bash
git clone https://github.com/jospindev-stack/auth-microservice.git
cd auth-microservice
```

## Configure environment

Linux / macOS

```bash
cp .env.example .env
```

Windows

```powershell
copy .env.example .env
```

Update your `.env` file:

```env
POSTGRES_PASSWORD=your_password
JWT_SECRET=your_random_secret_key
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
```

## Run

```bash
docker compose up -d --build
```

Application:

```text
http://localhost:8080
```

Swagger UI:

```text
http://localhost:8080/swagger
```

---

# Local Development

Go to the project:

```bash
cd AuthMicroservice
```

Configure secrets:

```bash
dotnet user-secrets set "ConnectionStrings:DefaultConnection" "Host=localhost;Database=authdb;Username=postgres;Password=postgres"
dotnet user-secrets set "JwtSettings:SecretKey" "your-secret-key"
dotnet user-secrets set "Authentication:Google:ClientId" "your_client_id"
dotnet user-secrets set "Authentication:Google:ClientSecret" "your_client_secret"
```

Run the project:

```bash
dotnet run
```

Swagger:

```text
http://localhost:5000/swagger
```

---

# Running Tests

Run the full test suite from the repository root:

```bash
dotnet test AuthMicroservice.sln
```

The authentication tests use SQLite in-memory to preserve relational database behavior while keeping the test suite isolated and fast.

Current coverage includes:

- successful registration
- password confirmation validation
- duplicate email detection
- successful login
- invalid credentials
- disabled accounts
- refresh token rotation
- refresh token reuse detection
- refresh token revocation

---

# Continuous Integration

The GitHub Actions workflow runs automatically on pushes to `main`, pushes to `test/**` branches, and pull requests targeting `main`.

The pipeline performs:

```text
restore
  -> build (Release)
  -> test
```

Changes are expected to compile and pass the automated test suite before being merged.

---

# API Endpoints

## Authentication

| Method | Endpoint             | Authentication |
| ------ | -------------------- | -------------- |
| POST   | `/api/auth/register` | No             |
| POST   | `/api/auth/login`    | No             |
| POST   | `/api/auth/refresh`  | No             |
| POST   | `/api/auth/logout`   | Yes            |
| GET    | `/api/auth/me`       | Yes            |

## OAuth

| Method | Endpoint                     |
| ------ | ---------------------------- |
| GET    | `/api/oauth/google`          |
| GET    | `/api/oauth/google/callback` |

## Health

| Method | Endpoint  |
| ------ | --------- |
| GET    | `/health` |

---

# Example Request

## Register

```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "alice@example.com",
  "username": "alice",
  "password": "SecurePass123!",
  "confirmPassword": "SecurePass123!"
}
```

Response

```json
{
  "accessToken": "...",
  "refreshToken": "...",
  "expiresIn": 900,
  "user": {
    "id": "...",
    "email": "alice@example.com",
    "username": "alice"
  }
}
```

---

# Security

## Passwords

- BCrypt hashing
- Work factor 12
- Plain passwords are never stored

## JWT

- HS256
- 15-minute expiration
- Configurable issuer and audience

## Refresh Tokens

- 7-day lifetime
- Rotated on every refresh
- Previous refresh token revoked immediately

## Reuse Detection

If a revoked refresh token is used again, all active sessions belonging to that user are revoked.

## Rate Limiting

Authentication endpoints are protected against brute-force attacks using a configurable fixed-window rate limiter.

---

# Environment Variables

| Variable                                | Description                  |
| --------------------------------------- | ---------------------------- |
| ConnectionStrings__DefaultConnection    | PostgreSQL connection string |
| JwtSettings__SecretKey                  | JWT signing key              |
| JwtSettings__Issuer                     | JWT issuer                   |
| JwtSettings__Audience                   | JWT audience                 |
| JwtSettings__AccessTokenExpiryMinutes   | Access token lifetime        |
| JwtSettings__RefreshTokenExpiryDays     | Refresh token lifetime       |
| Authentication__Google__ClientId        | Google Client ID             |
| Authentication__Google__ClientSecret    | Google Client Secret         |
| FrontendUrl                             | Frontend callback URL        |

---

# Google OAuth Setup

1. Open Google Cloud Console.
2. Create OAuth 2.0 credentials.
3. Select **Web Application**.
4. Add:

```text
http://localhost:8080/api/oauth/google/callback
```

5. Copy the Client ID and Client Secret into your `.env`.

---

# Deployment

The application can be deployed to platforms that support .NET or Docker containers, including Azure App Service and container-based hosting platforms.

Health endpoint:

```text
GET /health
```

---

# Roadmap

Future improvements:

- Email verification
- Password reset
- Multi-factor authentication (MFA)
- Redis distributed cache
- Redis refresh token storage
- API-level integration tests
- Deployment automation

---

# License

This project is licensed under the **MIT License**.

---

## Author

**Jospin Meka**

Software Developer

GitHub: https://github.com/jospindev-stack
