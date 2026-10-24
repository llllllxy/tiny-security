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

## Scope (please read first)

This framework handles **authentication + authorization decisions only**: identity authentication, session
lifecycle, annotation/URL-based authorization, exception translation, secure defaults and config validation.

**Explicitly out of scope** (implement these in your business project):

- **Data-level permissions / row-level filtering** (e.g. "own records only", "own department and below")
- **Role inheritance**, permission trees, menu/button-permission data models
- Admin UI for permission management

Rationale: rules like "own / own department / custom" depend on *your* business schema
(e.g. `sys_user` / `sys_dept` / `sys_role_dept`); a framework cannot get them right without assuming a data
model it does not own. For reference, **Spring Security** stops at `AuthorizationManager` / `GrantedAuthority`
and **Shiro** at `Realm` + `WildcardPermission` — **neither provides data-level permissions**. Such features
are typically implemented inside business scaffolds (e.g. RuoYi).

> To decide whether a capability belongs here, ask: "Does Spring Security do this?"


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
   # Positive integers only: 0 or a negative value makes the application fail at startup
   # (never-expiring sessions are considered an anti-pattern and are not supported)
   timeout: 1800
   # Max concurrent logins per account, 0 = unlimited (default)
   max-concurrent-logins: 2
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
    # Token signing secret. Strongly recommended to set a fixed high-entropy random value.
    # If unset, a temporary random secret is generated: all sessions invalidate on restart, and in a
    # multi-instance deployment the instances will not accept each other's tokens.
    token-secret: your-secret-key-please-replace-me
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
// AuthUtil resolves AuthProvider from the current request's WebApplicationContext on every call.
// It is NOT a static facade backed by a mutable global (that design was removed in 1.5.0).
// Note: it only works on threads that own the current request; in @Async / MQ threads it throws
// UnAuthorizedException -- inject AuthProvider directly for those cases.
// Note (>=1.4.0): these methods throw UnAuthorizedException when not logged in.
Object loginId = AuthUtil.getLoginId();
String loginIdStr = AuthUtil.getLoginIdAsString();
Set<String> roles = AuthUtil.getRoleSet();
boolean isAdmin = AuthUtil.hasRole("admin");
```

### 2.2.5 List all session credentials of an account

Returns all **valid (non-expired)** session credentials of an account — useful for
multi-device management (list online devices) or targeted kick-out (revoke one
credential instead of all sessions). Returns an empty list (never `null`) when the
account has no valid session.

```java
@Autowired
private AuthProvider authProvider;

List<String> credentialsList = authProvider.getCredentialsByLoginId(loginId);

// Typical usage: revoke only one session (device), keep the others
authProvider.deleteByCredentials(credentialsList.get(0));
```

> ⚠️ A credential **is** the session key — never write it to logs or return it to clients.
> This method relies on an "account → credentials" reverse index. All four built-in
> repositories (single / caffeine / redis / jdbc) support it; a custom `SessionRepository`
> that does not override it throws `UnsupportedOperationException`.

### 2.2.6 Query all online users

`getCredentialsByLoginId` answers "which devices is *this* account online on?".
The methods below answer "**who** is online right now?".

```java
@Autowired
private AuthProvider authProvider;

// 1. Online account ids (deduplicated; multi-device login counts once). Elements are String.
List<Object> loginIds = authProvider.getOnlineLoginIds();

// 2. Number of online accounts (people, not sessions)
int onlineUserCount = authProvider.countOnlineUsers();

// 3. Session details (one entry per session; multi-device login yields multiple entries)
List<OnlineSession> sessions = authProvider.getOnlineSessions();

// 4. Kick one specific session; other devices of the same account stay logged in
authProvider.deleteBySessionId(session.getLoginId(), session.getSessionId());
```

**`OnlineSession` deliberately has no `credentials` field.** A credential *is* the signed
bearer token — returning it in a list response would hand over session takeover.
Instead each entry carries a `sessionId`: the **SHA-256 digest** of the credential.
It cannot be reversed into the credential (which is a 122-bit random UUID), but it is
enough for the backend to resolve the real credential and revoke it.

> ⚠️ `sessionId` is a digest, **not** an authentication token — anyone holding it can still call
> the kick-out API. Protect the kick-out endpoint the same way you protect the list endpoint.

**Performance (important).** These are *global* queries, and the cost depends heavily on `store-type`:

| store-type | Implementation | Cost |
|---|---|---|
| `jdbc` | one `SELECT DISTINCT login_id ... WHERE credentials_expire_time > ?` | lowest; index-friendly |
| `single` / `caffeine` | scans the in-memory index | O(accounts), no I/O |
| `redis` | `SCAN`s the online-list key prefix | **highest**, see below |

- `redis` uses **`SCAN`, not `KEYS`**: `KEYS` walks the whole keyspace in one shot and **blocks the
  single-threaded Redis** (sa-token hit exactly this bug and only switched to `SCAN` in v1.46.0).
  `SCAN` is cursor-based and never holds Redis for long — but it is still **O(total keys)**, plus one
  validity re-check per account. For a few thousand online accounts expect roughly
  **1–3 seconds** on a LAN Redis.
- For reference, sa-token publishes these numbers for its equivalent API (`StpUtil.searchSessionId`):
  **1M sessions, take 10 → 0.255s standalone / 3.322s on Redis.** Same order of magnitude.
- `getOnlineSessions()` is **more expensive** than `getOnlineLoginIds()`: after listing accounts it
  reads every session body one by one. Use `countOnlineUsers()` / `getOnlineLoginIds()` when you only
  need the count or the id list.

> ⚠️ **Do not call these on hot paths.** They are meant for on-demand admin queries. Traversal-based
> statistics inherently lag behind reality — for second-accurate presence, push updates over WebSocket.

Other notes:

- With `single` / `caffeine` in a **multi-instance deployment, only the local instance's sessions are
  returned**. Use `redis` or `jdbc` for a cluster-wide view.
- A custom `SessionRepository` that does not override these `default` methods throws
  `UnsupportedOperationException` — "unsupported" is reported loudly rather than silently
  returning an empty list.

### 2.2.7 Skip authorization with `@Ignore`

Annotate a controller method (or class) with `@Ignore` to bypass annotation-based authorization:

```java
@Ignore
@GetMapping("/public/health")
public Result<?> health() {
    return Result.ok();
}
```

> `@Ignore` is honored on parent classes and interfaces as well (1.5.0+): if a superclass/interface method
> carries the annotation, the overriding/implementing method inherits the behavior.

### 2.2.8 Passing the token from the front end

1. **Via header (recommended)**

```javascript
$.ajax({
    url: "/xxx",
    type: "GET",
    headers: { "token": token },
    success: function (data) { }
});
```

2. **Via URL parameter**

> ⚠️ **Disabled by default.** `tiny-security.enable-url-token` defaults to `false`, because tokens in URLs
> leak into access logs, browser history and the `Referer` header. To use it you must explicitly set
> `enable-url-token: true` (still **not recommended**).

### 2.2.9 Exception translation

The framework ships an exception resolver that converts framework exceptions into JSON responses.
Configure it via:

```yaml
tiny-security:
  exception-translation-enabled: true   # default true
  force-http-status: false              # default false; when true always returns HTTP 200
  exception-resolver-order:             # default null (equivalent to HIGHEST_PRECEDENCE)
```

If you prefer your own `@ControllerAdvice` to handle these exceptions first, set
`exception-resolver-order` to `0` or higher.

---

## 2.3 Samples & Docs

- Full usage: see [README.md](README.md) (Chinese)
- Upgrade log: [CHANGELOG.md](CHANGELOG.md)
