<h1 align="center">tiny-security</h1>

<p align="center">
	<a target="_blank" href="https://www.apache.org/licenses/LICENSE-2.0">
		<img src="https://img.shields.io/badge/license-Apache%202-green.svg" />
	</a>
	<a target="_blank" href="https://www.oracle.com/technetwork/java/javase/downloads/index.html">
		<img src="https://img.shields.io/badge/JDK-17+-blue.svg" />
	</a>
    <a href="https://github.com/llllllxy/tiny-security/stargazers">
       <img src="https://img.shields.io/github/stars/llllllxy/tiny-security?style=flat-square&logo=GitHub">
    </a>
    <a href="https://github.com/llllllxy/tiny-security/network/members">
        <img src="https://img.shields.io/github/forks/llllllxy/tiny-security?style=flat-square&logo=GitHub">
    </a>
    <a href="https://github.com/llllllxy/tiny-security/issues">
        <img src="https://img.shields.io/github/issues/llllllxy/tiny-security.svg?style=flat-square&logo=GitHub">
    </a>
    <a href='https://gitee.com/leisureLXY/tiny-security'>
        <img src='https://gitee.com/leisureLXY/tiny-security/badge/star.svg?theme=dark' alt='star' />
    </a>
    <br />
</p>

# 1. Introduction

tiny-security is a lightweight Java Web authentication & authorization framework based on Spring Boot, designed to make auth simple and efficient.

**Core features**
- Dual-layer protection: login authentication + permission/role authorization
- Two token modes: pure token (header) and cookie-based
- Pluggable session storage: Redis / JDBC / in-memory (single), customizable
- Adapts to both separated and non-separated front/back-end projects
- Complete documentation, usage examples and best practices

> The English README is a concise mirror of [README.md](README.md). For the most up-to-date content, refer to the Chinese version.

---

# 2. Quick Start

## 2.1 Spring Boot Integration

### 2.1.1 Prerequisites
- JDK 17+ (Spring Boot 3.x branch)
- Spring Boot 2.x or 3.x project

### 2.1.2 Add Dependency

Pick the starter matching your Spring Boot version:

**Spring Boot 2.x**
```xml
<dependency>
    <groupId>top.lxyccc</groupId>
    <artifactId>tiny-security-boot-starter</artifactId>
    <version>1.3.1</version>
</dependency>
```

**Spring Boot 3.x**
```xml
<dependency>
    <groupId>top.lxyccc</groupId>
    <artifactId>tiny-security-boot3-starter</artifactId>
    <version>1.4.0</version>
</dependency>
```

### 2.1.3 Configuration

```yaml
tiny-security:
   # Storage type: redis | jdbc | single (default, in-memory) | caffeine (local cache).
   # Note: caffeine is an optional dependency, add com.github.ben-manes.caffeine:caffeine yourself.
   store-type: single
   # Max entries for the caffeine repository (when store-type=caffeine), default 10000, approx LRU eviction.
   caffeine-maximum-size: 10000
   # Token name (also the cookie name when cookie mode is enabled).
   # Token is read in order: header -> cookie (only when enable-cookie=true).
   # URL parameter is NOT read by default (enable-url-token=false) since URL-borne tokens leak into access logs.
   token-name: token
   # Session timeout (seconds), default 1800 (30 min)
   timeout: 1800
   # Max concurrent logins per account, 0 = unlimited (default)
   max-concurrent-logins: 2
   # Credential style. Only uuid / random128 / nanoid are cryptographically random and safe for production.
   # Any other value falls back to uuid (snowflake/objectid/ulid were removed as predictable).
   credentials-style: uuid
   # Table name for JDBC storage, default t_auth_storage
   table-name: t_auth_storage
   # Enable permission/role checks, default false. When true, implement AuthorizationInfoGet.
   authorization-enabled: true
   # Enable the framework's default exception translator (converts framework exceptions to JSON), default true
   exception-translation-enabled: true
   # Force HTTP 200 for error responses, default false (returns real 401/403/409/500)
   force-http-status-200: false
   # Permission check mode: ANNOTATION (@RequiresPermissions/@RequiresRoles) | URL (ant-style path match)
   perm-check-mode: ANNOTATION
   # JWT secret. Strongly recommended to set a fixed high-entropy random value.
   # If unset, a temporary random secret is generated and all sessions invalidate on restart.
   jwt-secret: your-secret-key-please-replace-me
   # JWT subject, uses default if unset
   jwt-subject: tiny-security
   # JWT self expiry (seconds), default 2592000 (30 days). Effective value is max(jwt-timeout, timeout).
   jwt-timeout: 2592000
   # Cookie mode (login writes cookie, logout clears cookie, token read from cookie). Default false (pure token).
   enable-cookie: false
   # Allow reading token from URL parameter, default false (URL tokens leak into access logs/Referer)
   enable-url-token: false
   # Cookie Secure flag (HTTPS only), default false (enable for production)
   cookie-secure: false
   # Cookie SameSite, default LAX (options: STRICT/LAX/NONE, mitigates CSRF)
   cookie-same-site: LAX
   # Priority of the framework exception resolver. Default = HIGHEST_PRECEDENCE (handles security exceptions first).
   # Set to 0 or higher to let your @ControllerAdvice take precedence.
   exception-resolver-order: # e.g. 0
   # Paths to intercept, default all (/**)
   include-path: /**
   # Paths to exclude
   exclude-path:
      - /auth/login
      - /auth/getCode
      - /auth/register
      - /auth/sendEmail
```

### 2.1.4 Session Storage Setup

**JDBC storage** — requires `spring-boot-starter-jdbc` and importing the provided SQL script (MySQL version provided):
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-jdbc</artifactId>
</dependency>
```

**Redis storage** — requires `spring-boot-starter-data-redis`:
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
```

### 2.1.5 Implement AuthorizationInfoGet (SPI)

When `authorization-enabled=true`, implement `AuthorizationInfoGet` to provide permission/role codes:

```java
@Component
public class AuthorizationInfoGetImpl implements AuthorizationInfoGet {

    @Override
    public Set<String> getPermissionSet(LoginSubject subject) {
        // Return the permission codes owned by this account
        return Set.of("user:read", "user:write");
    }

    @Override
    public Set<String> getRoleSet(LoginSubject subject) {
        // Return the role identifiers owned by this account
        return Set.of("admin", "user");
    }
}
```

---

## 2.2 Session Authentication

### 2.2.1 Login (create session)

```java
@RestController
public class LoginController {

    @Autowired
    private AuthProvider authProvider;

    @PostMapping("/login")
    public Result<Object> login(@RequestParam String username, @RequestParam String password) {
        // 1. Your credential verification logic
        if (!verifyUser(username, password)) {
            return Result.fail("invalid username or password");
        }
        // 2. Issue token (loginId must be globally unique, e.g. user id or username)
        String token = authProvider.login(username);
        // Optionally carry extra session info
        // String token = authProvider.login(username, Map.of("userId", entity.getId()));
        return Result.ok("login success", token);
    }

    private boolean verifyUser(String username, String password) {
        return "admin".equals(username) && "123456".equals(password);
    }
}
```

### 2.2.2 Logout (destroy session)

```java
@PostMapping("/logout")
public Result<Void> logout() {
    authProvider.logout();
    return Result.ok();
}
```

### 2.2.3 Annotation-based authorization

```java
// Requires ALL of the permissions (logical = AND)
@RequiresPermissions(value = {"user:read", "user:write"}, logical = Logical.AND)
@GetMapping("/user/detail")
public Result<User> detail() { ... }

// Requires ANY of the roles (logical = OR)
@RequiresRoles(value = {"admin", "superAdmin"}, logical = Logical.OR)
@PostMapping("/user/delete")
public Result<Void> delete() { ... }
```

### 2.2.4 Read current user

```java
// AuthUtil is a static facade delegating to the framework context.
// Note (>=1.4.0): these methods throw UnAuthorizedException when not logged in.
Object loginId = AuthUtil.getLoginId();
String loginIdStr = AuthUtil.getLoginIdAsString();
Set<String> roles = AuthUtil.getRoleSet();
boolean isAdmin = AuthUtil.hasRole("admin");
```

---

## 2.3 Samples & Docs

- Full usage: see [README.md](README.md) (Chinese)
- Upgrade log: [CHANGELOG.md](CHANGELOG.md)
- Security audit & roadmap: `docs/security-audit-and-roadmap-2026-09.md`
