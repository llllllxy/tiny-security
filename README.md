<h1 align="center">tiny-security</h1>


<p align="center">
	<a target="_blank" href="https://www.apache.org/licenses/LICENSE-2.0">
		<img src="https://img.shields.io/badge/license-Apache%202-green.svg" />
	</a>
	<a target="_blank" href="https://www.oracle.com/technetwork/java/javase/downloads/index.html">
		<img src="https://img.shields.io/badge/JDK-17%2B-blue.svg" />
	</a>
    <a href="https://github.com/llllllxy/tiny-security/stargazers">
       <img src="https://img.shields.io/github/stars/llllllxy/tiny-security?style=flat-square&logo=GitHub">
    </a>
    <a href="https://github.com/llllllxy/tiny-security/network/members">
        <img src="https://img.shields.io/github/forks/llllllxy/tiny-security?style=flat-square&logo=GitHub">
    </a>
    <a href="https://github.com/llllllxy/tiny-security/watchers">
        <img src="https://img.shields.io/github/watchers/llllllxy/tiny-security?style=flat-square&logo=GitHub">
    </a>
    <a href="https://github.com/llllllxy/tiny-security/issues">
        <img src="https://img.shields.io/github/issues/llllllxy/tiny-security.svg?style=flat-square&logo=GitHub">
    </a>
    <a href='https://gitee.com/leisureLXY/tiny-security'>
        <img src='https://gitee.com/leisureLXY/tiny-security/badge/star.svg?theme=dark' alt='star' />
    </a>
    <br />
</p>

# 1、简介

tiny-security 是一款基于 SpringBoot 开发的轻量级 Java Web 权限认证框架，致力于让认证鉴权变得简单高效。
核心特性
- 支持登录认证与权限认证双重保障
- 兼容 token 验证与 cookie 验证两种模式
- 提供多种会话存储方案：redis、jdbc 和单机 session（支持自定义会话存储）
- 无缝适配前后端分离与不分离项目
- 完善的文档，包括使用说明、API文档、最佳实践等

## 框架边界（请先阅读）

本框架**只负责「认证 + 鉴权判定」**：身份认证、会话生命周期、注解/URL 鉴权判定、异常翻译、安全默认值与配置校验。

**明确不做**（请在你的业务项目内实现）：

- **数据权限 / 行级数据过滤**（如"仅本人""本部门及以下"）
- **角色继承**、权限树、菜单与按钮码的数据模型
- 权限的后台管理界面

原因：「本人 / 本部门 / 自定义」这类判定取决于你自己的业务表结构（如 `sys_user` / `sys_dept` / `sys_role_dept`），
框架无法在不假设一套数据模型的前提下做对。作为对照，**Spring Security** 的授权止于 `AuthorizationManager` / `GrantedAuthority`、
**Shiro** 止于 `Realm` + `WildcardPermission`，**两者都不提供数据权限** —— 这类能力通常由业务脚手架（如若依）在业务项目内实现。

> 想判断某个能力该不该进本框架，可以先问一句："Spring Security 做了吗？"


---

# 2、快速入门

## 2.1、SpringBoot集成

### 2.1.1 环境准备
- JDK 8 及以上版本
- SpringBoot 2.x 或 3.x 项目

### 2.1.2 引入依赖
根据 SpringBoot 版本选择对应的 starter：

**SpringBoot 2.x**
```xml
<dependency>
    <groupId>top.lxyccc</groupId>
    <artifactId>tiny-security-boot-starter</artifactId>
    <version>1.5.0</version>
</dependency>
```

**SpringBoot 3.x**
```xml
<dependency>
    <groupId>top.lxyccc</groupId>
    <artifactId>tiny-security-boot3-starter</artifactId>
    <version>1.5.0</version>
</dependency>
```

### 2.1.3 配置参数

```yaml
tiny-security:
   # 是否打印框架启动 banner，默认 true；设为 false 可关闭启动日志中的框架信息输出
   banner: true
   # 存储类型，目前支持jdbc、redis、single(单机内存)、caffeine(本地缓存)四种，如不配置，则默认为single
   # 注意：caffeine 为可选依赖，使用前需自行引入 com.github.ben-manes.caffeine:caffeine
   store-type: single
   # caffeine 会话仓储的最大缓存条目数（store-type=caffeine 时生效），默认10000，超出按近似LRU驱逐
   caffeine-maximum-size: 10000
   # token名称 (同时也是cookie名称以适配前后端不分离的模式)
   # 注意：token 依次从 header、Cookie（开启 enable-cookie 后）中读取；
   # 默认不再从 URL 参数读取（enable-url-token 默认 false），因为 URL 传 token 会进入访问日志，存在泄露风险
   token-name: token
   # 会话有效期（会话存储中的subject有效时长），单位秒，默认1800秒(30分钟)
   # 只允许正整数：配置 0 或负数会在启动时直接报错（会话永不过期是反模式，故不支持该配置方式）
   timeout: 1800
   # 最大登录并发数，默认不限制
   max-concurrent-logins: 2
   # 当配置为jdbc时，存储会话信息的表名字，默认为t_auth_storage
   # 建表脚本随 starter 一起发布，位于 tiny-security-boot-starter 的 resources/sql/t_auth_storage.sql
   # 使用 jdbc 存储时请先执行该脚本建表（脚本内含 credentials 唯一约束，用于凭证碰撞检测）
   # 注意：login_subject 列为 varchar(5000)，因此 extraInfo 序列化后不可超过该长度，否则登录会失败
   table-name: t_auth_storage
   # 是否开启权限(角色)校验，默认false不开启，开启后需要实现AuthorizationInfoGet接口
   authorization-enabled: true
   # 是否启用框架默认异常翻译器（自动将框架异常转换为JSON响应），默认true
   exception-translation-enabled: true
   # 是否强制以 HTTP 200 返回异常响应，默认false；开启后异常统一返回200，由响应体 code 字段表达真实错误
   force-http-status-200: false
   # 权限校验方式，可配置ANNOTATION（注解方式）、URL（url方式）
   perm-check-mode: ANNOTATION
   # token签名密钥，强烈建议配置固定的高强度随机值（不配置时框架会生成临时随机密钥：重启后所有会话将失效，多实例部署下各实例也互不认可对方的token）
   token-secret: your-secret-key-please-replace-me
   # 长度建议 >= 32 字节；短于 32 字节会在启动时打印 WARN（不阻止启动）
   # 是否启用Cookie模式（登录写cookie、登出清理cookie、从cookie读取token）
   # 默认false纯token模式（前后端分离）；前后端不分离项目需开启
   enable-cookie: false
   # 是否允许从 URL 参数读取 token，默认 false（URL 传 token 会进入访问日志/Referer，造成凭证泄露）
   enable-url-token: false
   # Cookie 是否仅通过 HTTPS 传输，默认false（本地 http 调试友好，生产环境建议开启）
   cookie-secure: false
   # Cookie SameSite 属性，默认LAX（可选 STRICT/LAX/NONE，用于防御 CSRF）
   cookie-same-site: LAX
   # 框架异常解析器优先级，默认null（等价HIGHEST_PRECEDENCE，尽早处理安全异常）
   # 若希望业务侧 @ControllerAdvice 优先处理，可设为 0 或更大的值
   exception-resolver-order: # 例如 0
   # 要拦截的路径，默认拦截所有路径
   include-path: /**
   # 要排除的路径，默认不排除任何路径
   exclude-path:
      - /auth/login
      - /auth/getCode
      - /auth/register
      - /auth/sendEmail
```

### 2.1.4 会话存储配置
- 当`store-type`配置为`jdbc`时，需要配置数据库连接信息，并导入框架提供的sql脚本到数据库中（目前仅提供了MySQL版本）
- 当`store-type`配置为`redis`时，需要配置redis连接信息


1. **使用jdbc做会话存储容器**

>  依赖于`jdbcTemplate`，须导入依赖 `spring-boot-starter-jdbc`，在yml里进行数据库连接的相应配置并导入框架提供的sql脚本（目前仅提供了MySQL版本）
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-jdbc</artifactId>
</dependency>
```


2. **使用redis做会话存储容器**

>  依赖于`stringRedisTemplate`，须导入依赖 `spring-boot-starter-data-redis` ，并在yml里进行redis连接的相应配置
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
```


### 2.1.5 实现AuthorizationInfoGet接口
>  如需开启权限(角色)校验，还需要实现`AuthorizationInfoGet`接口，提供权限和角色编码数据（框架没有对权限和角色标记码进行缓存，如需缓存请自行处理）

```java
@Component
public class AuthorizationInfoGetImpl implements AuthorizationInfoGet {
    private final static Logger logger = LoggerFactory.getLogger(AuthorizationInfoGetImpl.class);


    /**
     * 返回一个账号所拥有的权限码集合
     * @param subject 登录主体，包含loginId、登录凭证等信息
     */
    @Override
    public Set<String> getPermissionSet(LoginSubject subject) {
        if (logger.isInfoEnabled()) {
            logger.info("AuthorizationInfoGet -- getPermissionSet -- subject = {}", subject);
        }
        // 自定义权限编码列表获取逻辑，下面的只是示例
        Set<String> permissionSet = new HashSet<String>() {{
            add("user:read");
            add("user:write");
        }};

        return permissionSet;
    }

    /**
     * 返回一个账号所拥有的角色标识集合 (权限与角色可分开校验)
     * @param subject 登录主体，包含loginId、登录凭证等信息
     */
    @Override
    public Set<String> getRoleSet(LoginSubject subject) {
        if (logger.isInfoEnabled()) {
            logger.info("AuthorizationInfoGet -- getRoleSet -- subject = {}", subject);
        }
        // 自定义角色编码列表获取逻辑，下面的只是示例
        Set<String> roleSet = new HashSet<String>() {{
            add("admin");
            add("user");
        }};
        return roleSet;
    }
}
```

---

## 2.2、会话认证

### 2.2.1 登录认证，创建会话

```java
@RestController
public class LoginController  {
    
    @Autowired
    private AuthProvider authProvider;
    
    @PostMapping("/login")
    public Result<Object> login(@RequestParam("username") String username,
                                @RequestParam("password") String password) {
        // 1. 你的登录验证逻辑，例如：校验用户名密码是否正确
        if (!verifyUser(username, password)) {
            return Result.fail("用户名或密码错误！");
        }
        
        // 2. 签发token（loginId建议使用用户ID或用户名，需保证全局唯一）
        String token = authProvider.login(username);
        
        // 或额外携带其他会话信息，例如：用户id、用户名、手机号、邮箱等等
       // String token = authProvider.login(username, Map.of("userId", entity.getId()));
       
        return Result.ok("登录成功！", token);
    }

   // 自定义用户校验
   private boolean verifyUser(String username, String password) {
      // 实际项目中对接数据库验证
      return "admin".equals(username) && "123456".equals(password);
   }
}
```
> 注意：`login` 返回的 `token` 默认已带 `Bearer ` 前缀（例如 `Bearer eyJ...`），前端传递时应原样携带。
login方法参数说明：
- loginId  登录的账号id，建议的数据类型：long | int | String，建议为用户id，不可以传入复杂类型，如：User、Admin 等等

---

### 2.2.2 退出登录，注销会话

```java
@Controller
public class IndexController {
   
    @Autowired
    private AuthProvider authProvider;

    @ResponseBody
    @GetMapping("/logout")
    public Result<Object> logout(HttpServletRequest request) {
        // 退出登录，注销会话
        authProvider.logout(request);
        
        // 不传入request亦可，会自动获取当前的request
        // authProvider.logout();

        return Result.ok("退出登录成功！");
    }
}
```

### 2.2.3 获取当前登录会话
```java
@Autowired
private AuthProvider authProvider;

// 获取登录ID，无会话时会抛出异常
Object loginId = authProvider.getLoginId();
String loginIdStr = authProvider.getLoginIdAsString();
Long loginIdLong = authProvider.getLoginIdAsLong();

// 获取登录安全上下文，无会话时会抛出异常
LoginSubject loginSubject = authProvider.getLoginSubject();
```

也可使用静态工具类 `AuthUtil`（行为与 `AuthProvider` 一致，**无会话时同样抛 `UnAuthorizedException`**）：
```java
// 无会话时抛 UnAuthorizedException（不是返回 null）
Object loginId = AuthUtil.getLoginId();
String loginIdStr = AuthUtil.getLoginIdAsString();
Integer loginIdInt = AuthUtil.getLoginIdAsInt();
Long loginIdLong = AuthUtil.getLoginIdAsLong();

// 无会话时抛 UnAuthorizedException（不是返回 null）
SecurityContext securityContext = AuthUtil.getSecurityContext();
LoginSubject loginSubject = securityContext.getLoginSubject();
```

> **注意**：`AuthUtil` 只适用于**持有当前请求的线程**。在 `@Async`、`Callable`、`DeferredResult`、
> MQ 消费线程等非 Web 线程里调用会取不到请求、抛 `UnAuthorizedException` —— 这类场景请直接注入 `AuthProvider`。
> 这是有意取舍而非缺陷：线程绑定的上下文（同 `RequestContextHolder`）切线程后本就失效。

---

### 2.2.4 获取当前登录用户token
```java
@Autowired
private AuthProvider authProvider;

// 返回带 "Bearer " 前缀的完整 token（与 login() 的返回值同形，可直接放回请求头使用）
String token = authProvider.getToken();
// 或者
String token = authProvider.getToken(HttpServletRequest);

// 若需要不带前缀的裸值（credentials.signature），用 getRawToken()
String rawToken = authProvider.getRawToken();
String rawToken2 = authProvider.getRawToken(HttpServletRequest);
```

> 提示：`getToken()` 自 `1.5.0` 起返回**带 `Bearer ` 前缀**的值（此前返回去前缀的裸值）。
> 若你的代码依赖旧行为，请改用 `getRawToken()`。
---

### 2.2.5 获取当前登录用户凭证（对应redis或database里的唯一键）
```java
@Autowired
private AuthProvider authProvider;

String credentials = authProvider.getCredentials();
// 或者
String credentials = authProvider.getCredentials(HttpServletRequest);
```

---

### 2.2.6 使用会话验证忽略注解 `@Ignore`
在Controller的方法或类上面添加`@Ignore`注解可排除框架会话拦截，即表示调用接口不用传递token了。

---

### 2.2.7 会话主动注销
```java
@Autowired
private AuthProvider authProvider;

// 根据token，使会话注销
authProvider.deleteByToken(token);

// 根据会话凭证credentials，使会话注销
authProvider.deleteByCredentials(credentials);

// 根据用户loginId，使该用户的全部会话都注销
authProvider.deleteByLoginId(loginId);

```

### 2.2.8 查询指定账号的全部会话凭证

获取某个账号当前所有**有效（未过期）**的会话凭证，常用于多设备管理（列出账号的所有在线设备/会话）、
定向踢人（只注销其中某一个凭证，而非 `deleteByLoginId` 的全量注销）。
账号无有效会话时返回空列表（不会返回 null）。

```java
@Autowired
private AuthProvider authProvider;

// 获取该账号当前所有有效会话凭证
List<String> credentialsList = authProvider.getCredentialsByLoginId(loginId);

// 典型用法：只注销该账号的某一个会话（设备），保留其他会话
authProvider.deleteByCredentials(credentialsList.get(0));
```

> ⚠️ 凭证即会话钥匙，等同于用户身份凭据，**请勿输出到日志或返回给前端**。
> 该方法依赖仓储的「账号 → 凭证」反向索引，内置四种仓储（single / caffeine / redis / jdbc）均已支持；
> 自定义 `SessionRepository` 未实现该方法时，调用会抛 `UnsupportedOperationException`。

### 2.2.9 查询全量在线用户

「谁现在在线」是全局维度的查询。上一节的 `getCredentialsByLoginId` 回答的是"某个人在哪些设备上在线"，
本节的方法回答的是"现在一共有谁在线"。

```java
@Autowired
private AuthProvider authProvider;

// 1、在线账号ID列表（去重，一个账号多端登录只算一个）；元素统一为 String
List<Object> loginIds = authProvider.getOnlineLoginIds();

// 2、在线账号数（去重后的「人」数，不是会话数）
int onlineUserCount = authProvider.countOnlineUsers();

// 3、在线会话明细（每一份会话一条，同一账号多端登录会有多条）
List<OnlineSession> sessions = authProvider.getOnlineSessions();
for (OnlineSession session : sessions) {
    System.out.println(session.getLoginId());          // 账号ID
    System.out.println(session.getLoginTime());        // 登录时间
    System.out.println(session.getSessionId());        // 会话标识（用于踢人）
    System.out.println(session.getExtraInfo());        // 登录时存入的扩展信息（IP/设备等）
}

// 4、按会话标识踢出指定会话（定向下线，同账号其它设备不受影响）
authProvider.deleteBySessionId(session.getLoginId(), session.getSessionId());
```

**关于 `sessionId`：列表接口不返回凭证，只返回它的 SHA-256 摘要。**

凭证就是 bearer token 的签名原文，等同于用户身份凭据——一旦出现在列表接口的响应体里，
拿到响应的人就能直接接管会话。因此 `OnlineSession` **刻意不含 `credentials` 字段**，
改为提供 `sessionId`（凭证摘要）用于定位会话：它不可逆推凭证（凭证是 122 bit 随机 UUID），
但足以让后端反查出真凭证并踢出。业务代码全程不需要接触原始凭证。

> ⚠️ `sessionId` 是摘要，**不是身份凭证，也不做鉴权**。拿到 `sessionId` 的人同样可以调用踢人接口，
> 因此踢人接口仍必须与列表接口做同等的权限校验。

**分页**：框架不内置分页（分页模型是业务概念），返回的是全量结果。在线量较大时请在业务侧自行分页或缓存。

#### 性能说明（重要）

这四个方法都是**全局查询**，开销与 `store-type` 强相关：

| store-type | 实现 | 开销 |
|---|---|---|
| `jdbc` | 一条 `SELECT DISTINCT login_id ... WHERE credentials_expire_time > ?` | 最低，可走索引；`countOnlineUsers` 已下推为 `COUNT(DISTINCT login_id)` |
| `single` / `caffeine` | 遍历本地内存索引 | O(账号数) 纯内存操作，无 IO |
| `redis` | `SCAN` 在线列表 key 前缀 | **最贵**，见下文 |

- **`redis` 用 `SCAN` 而不是 `KEYS`**：`KEYS` 会一次性遍历整个 key 空间，在 key 数量多时**阻塞 Redis 单线程**
  （sa-token 的同类 API 早期就踩过这个坑，其 v1.46.0 才改为 `SCAN`）。`SCAN` 是游标式分批遍历，不会长时间占住 Redis。
  但它仍是 **O(全库 key 数)** 的遍历，且每个账号还要回查一次有效会话。
  **按"几千在线账号、人均 1~2 个会话"估算，大致是万级 Redis 往返（局域网约 1~3 秒）。**
- **`getOnlineSessions()` 比 `getOnlineLoginIds()` 更贵**：拿到名单后还要对每份会话各读一次会话主体。
  只需要人数或名单时，请用 `countOnlineUsers()` / `getOnlineLoginIds()`。

> ⚠️ **请勿高频调用**。这些方法适合运维后台按需查询，**不要放进每次请求都要走的链路，也不要做成高频轮询接口**。
> 需要精确到秒的实时在线状态，请用 WebSocket 推送——遍历式统计天然滞后于真实状态
> （扫描与读取之间存在时间差，期间登录/登出/过期的会话可能出现在结果里或被漏掉）。

**其它注意点：**

- **`single` / `caffeine` 多实例部署下只返回本实例的数据**（本地内存存储，每个 JVM 持有自己的一份会话）。
  需要全局视图请用 `redis` 或 `jdbc`。
- **自定义 `SessionRepository` 未实现这些方法时，调用会抛 `UnsupportedOperationException`**
  （接口上是 `default` 方法，这样设计是为了不破坏升级前已有的自定义实现，同时让"不支持"被明确报错而非静默返回空列表）。
- jdbc 存储在在线账号量较大时，建议在 `(credentials_expire_time)` 或 `(login_id, credentials_expire_time)` 上建索引；
  过期行由清理线程按 24 小时周期删除，在此之前它们留在表里。

---


## 2.3、权限认证

### 2.3.1 注解方式控制权限和角色

**1.注解解释：**

```java
// 需要有 system:user:add 权限才能访问
@RequiresPermissions("system:user:add")

// 需要有 system:user:add 和 system:user:delete 权限才能访问, logical可以不写,默认是AND
@RequiresPermissions(value={"system:user:add", "system:user:delete"}, logical=Logical.AND)

// 需要有 system:user:add 或 system:user:delete 权限才能访问
@RequiresPermissions(value={"system:user:add", "system:user:delete"}, logical=Logical.OR)

// 需要有user角色才能访问
@RequiresRoles(value="user")

// 需要有admin和user角色才能访问
@RequiresRoles(value={"admin", "user"}, logical=Logical.AND)

// 需要有admin或user角色才能访问
@RequiresRoles(value={"admin", "user"}, logical=Logical.OR)
```

> 注解加在Controller的方法或类上面

**2.代码示例：**

```java
@Controller
public class IndexController {
    final static Logger logger = LoggerFactory.getLogger(IndexController.class);
    
    @Autowired
    private AuthProvider authProvider;

    @RequiresPermissions("权限3")
    @ResponseBody
    @GetMapping("/testPermission")
    public Result<Object> testPermission() {
        return Result.ok("testPermission测试成功！");
    }

    @RequiresRoles(value="角色1")
    @ResponseBody
    @GetMapping("/testRole")
    public Result<Object> testRole() {
        logger.info("SecurityContext = {}", authProvider.getSecurityContext());
        logger.info("authProvider.getLoginId() = {}", authProvider.getLoginId());
        logger.info("AuthUtil.getLoginId() = {}", AuthUtil.getLoginId());
        logger.info("token = {}", authProvider.getToken());
        return Result.ok("testRole测试成功！", authProvider.getLoginId());
    }
}
```

---

### 2.3.2 代码方式手动控制权限和角色
**1.代码示例：**

```java

// 判断：当前账号是否含有指定角色, 返回 true 或 false
AuthUtil.hasRole("role1");

// 判断：当前账号是否含有指定角色 [指定多个，必须全部验证通过]
AuthUtil.hasAllRole("role1", "role2");

// 判断：当前账号是否含有指定角色 [指定多个，只要其一验证通过即可]
AuthUtil.hasAnyRole("role1", "role2");

// 判断：当前账号是否含有指定权限, 返回 true 或 false
AuthUtil.hasPermission("permission1");

// 判断：当前账号是否含有指定权限 [指定多个，必须全部验证通过]
AuthUtil.hasAllPermission("permission1", "permission2");

// 判断：当前账号是否含有指定权限 [指定多个，只要其一验证通过即可]
AuthUtil.hasAnyPermission("permission1", "permission2");

```

### 2.3.3 直接通过URL控制权限（不支持角色校验）
AuthorizationInfoGet实现类里返回的权限编码要和接口URL相匹配（需要带上context-path）

**可选：限定 HTTP Method（1.5.0 新增）**

权限码可以写成 `METHOD 路径`（中间一个空格，Method 大小写不敏感）：

| 权限码写法 | 匹配语义 |
|---|---|
| `/user/**` | 匹配**任意** Method（与 1.5.0 之前一致，存量配置无需改动） |
| `GET /user/**` | 只匹配 GET |
| `POST /user/**` | 只匹配 POST |
| `* /user/**` | 匹配任意 Method（与不写 Method 等义） |

> ⚠️ **建议显式限定 Method**：不写 Method 时，「拥有 `GET /user` 读权限」等价于「拥有
> `DELETE /user` 权限」。读写分离的接口请写成 `GET /user/**` 与 `POST /user/**` 两条。

> ⚠️ **context-path 警告**：权限码匹配的是**含 context-path 的完整 URI**（例如应用配了
> `/api`，实际请求 URI 是 `/api/user/list`）。**修改应用的 context-path 会导致既有权限码
> 全部失配**，表现为原本有权限的用户全部 403（fail-closed，不会越权，但需要同步调整配置）。
> 若确实要改 context-path，请一并更新所有权限码。

---

### 2.3.3 权限通配符的使用
> 🚨支持使用通配符指定泛权限，例如当一个账号拥有system:user:*的权限时，system:user:add、system:user:delete、system:user:update都将匹配通过

> ⚠️注意
> 当一个账号拥有 `*` 权限时，可以验证通过任何权限码 （角色认证同理）, 所以请谨慎使用 `*` 权限码

---

## 2.4、异常处理
tiny-security在会话验证失败和权限验证失败的会抛出自定义异常：

| 自定义异常                 | 描述          | 错误信息                     |
|:----------------------|:-------------|:-------------------------|
| TinySecurityException | 基础异常 | 错误信息“系统异常！”，错误码500  |
| UnAuthorizedException | 未登录或会话已失效 | 错误信息“未登录或会话已失效！”，错误码401  |
| NoPermissionException | 无权限访问（角色或者资源不匹配）  | 错误信息“无权限访问！”，错误码403      |
| ConcurrentLoginOverLimitException | 并发登录超过限制 | 错误信息“并发登录超过最大限制！”，错误码409 |

默认情况下，框架已内置异常翻译器，会自动将上述异常转换为JSON响应（可通过 `tiny-security.exception-translation-enabled=false` 关闭）。

### 2.4.1 控制异常响应的 HTTP 状态码

默认情况下，框架会返回与异常对应的真实 HTTP 状态码（401 / 403 / 409 / 500），方便网关、前端按状态码做统一拦截。

如果你的前端或网关希望**所有异常都统一返回 HTTP 200**，仅通过响应体里的 `code` 字段区分错误（例如某些前端框架对 4xx/5xx 有额外拦截、或需要与旧系统兼容），可开启以下配置：

```yaml
tiny-security:
  # 是否强制以 HTTP 200 返回异常响应，默认 false
  # true  : 异常统一返回 200，响应体 code 仍为真实业务错误码（401/403/409/500），不影响前端判错
  # false : 返回真实错误状态码（401/403/409/500）
  force-http-status-200: true
```

> 说明：开启 `force-http-status-200: true` 后，HTTP 状态码固定为 200，但响应体中的 `code` 字段仍然是真实的业务错误码，前端仍可据此判断具体错误类型，无需改动判错逻辑。

如果你希望完全自定义返回结构，也可以自己编写全局异常处理器来接管返回：

```java
@ControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

   /**
    * 统一处理 TinySecurityException 及其子类异常（UnAuthorizedException、NoPermissionException、ConcurrentLoginOverLimitException）
    *
    * @param e 父类 TinySecurityException（实际接收子类实例）
    */
   @ExceptionHandler(TinySecurityException.class)
   public ApiResult<?> handleAuthException(TinySecurityException e) {
      // 判断具体异常类型
      if (e instanceof UnAuthorizedException) {
         // 未会话异常：使用子类的错误码
         return ApiResult.fail(e.getCode(), e.getMessage());
      } else if (e instanceof NoPermissionException) {
         // 无权限异常：使用子类的错误码
         return ApiResult.fail(e.getCode(), e.getMessage());
      } else if (e instanceof ConcurrentLoginOverLimitException) {
         // 并发登录超过最大限制：使用子类的错误码
         return ApiResult.fail(e.getCode(), e.getMessage());
      } else {
         // 兜底：处理 TinySecurityException 其他可能的子类（避免漏判）
         log.warn("未明确处理的 TinySecurityException 子类：{}，错误码：{}", e.getClass().getName(), e.getCode());
         return ApiResult.fail(e.getCode(), e.getMessage());
      }
   }
}
```

---

## 2.5、其他更多用法

### 2.5.1 前端传递token
> ⚠️ **方式 1（URL 参数传 token）默认被禁用**：`tiny-security.enable-url-token` 默认为 `false`，
> 因为 URL 上的 token 会进入**访问日志、浏览器历史与 Referer 头**，造成凭证泄露。
> 若确需使用，必须在配置中显式开启 `enable-url-token: true`（仍**不推荐**）。
> 推荐使用下方的方式 2（header）。

1. 放在参数里面用`token`传递（需显式开启 `enable-url-token: true`）：
```javascript
$.get("/xxx", { "token": token }, function(data) {

});
```
2. 放在header里面用`token`传递：
```javascript
$.ajax({
   url: "/xxx", 
   beforeSend: function(xhr) {
       // token应包含Bearer前缀，例如：Bearer eyJ...
       xhr.setRequestHeader("token", token);
   },
   success: function(data){ }
});
```
3. 前后端不分离的项目在开启 `enable-cookie: true` 后会自动从cookie里获取`token`（登录时也会自动写入cookie）

---

### 2.5.2 自定义SessionRepository
框架内置了 `JdbcSessionRepository`、`RedisSessionRepository` 和 `SingleSessionRepository` 三种会话仓储实现。
如果你想把会话存储到其他介质（例如 MongoDB），可以自定义 `SessionRepository`：

```java
@Component
@ConditionalOnProperty(name = "tiny-security.store-type", havingValue = "mongo")
public class MongoSessionRepository implements SessionRepository {
    @Override
    public boolean save(LoginSubject subject, int timeoutSeconds, int maxConcurrentLogins) {
        // 保存会话
        return true;
    }

    @Override
    public boolean checkByCredentials(String credentials) {
        return false;
    }

    @Override
    public LoginSubject getSubject(String credentials) {
        return null;
    }

    @Override
    public boolean refreshByCredentials(String credentials, LoginSubject subject, int timeoutSeconds) {
        return true;
    }

    @Override
    public boolean deleteByCredentials(String credentials) {
        return true;
    }

    @Override
    public boolean deleteByLoginId(Object loginId) {
        return true;
    }

    @Override
    public int countValidOnlineSessions(Object loginId) {
        return 0;
    }

    // 可选实现：按账号反查全部有效会话凭证（多设备管理/定向踢人场景需要）
    // 接口为 default 方法，不实现时调用会抛 UnsupportedOperationException
    @Override
    public List<String> getCredentialsByLoginId(Object loginId) {
        return Collections.emptyList();
    }

    // 可选实现：全量在线账号查询（「在线用户列表」场景需要，见 2.2.9）
    // 两个都是 default 方法，不实现时调用会抛 UnsupportedOperationException；
    // 只实现 getOnlineLoginIds 即可，countOnlineUsers 默认按它的 size() 计算
    @Override
    public List<Object> getOnlineLoginIds() {
        return Collections.emptyList();
    }

    // 存储层若能一条命令完成计数（如 SQL 的 COUNT DISTINCT），建议覆写本方法
    @Override
    public int countOnlineUsers() {
        return 0;
    }
}
```

- 配置
```yaml
tiny-security:
  store-type: mongo
```


### 2.5.3 摘要算法与密码哈希

如需对称/非对称加密，推荐直接使用 JDK JCA 或 Hutool、BouncyCastle 等专用密码学库。

#### 1. 摘要算法（`SimpleHash`）

> ⚠️ **`SimpleHash` 是摘要工具，不是密码哈希算法，请勿用于存储用户口令。**
>
> 它把 MD5 / SHA-1 当作一等算法名，而这两者早已不适合任何安全用途；其 `iterations`
> 参数只是**裸摘要的重复计算链**，**不是** PBKDF2 / scrypt / Argon2 这类具备内存硬度、
> 抗 GPU 暴破的密钥派生函数；构造器允许不传盐（即无每用户随机盐）；并且**不提供任何校验 API**
> —— 调用方只能自己写 `String.equals` 比对，会重新引入时序侧信道。
>
> **需要密码哈希请用下方的 `BCrypt`**；完整性校验、缓存键、去重指纹等非安全场景再用本工具。

支持 JDK 内置算法（MD5、SHA-1、SHA-256 等）与国密 SM3，可输出 HEX 或 Base64：

```java
    // 三参：算法 + 明文 + 盐（迭代 1 次）
    new SimpleHash("MD5", "123456", "323@#@$1234da").toHex();
    // 四参：末位为迭代次数，最少 1 次
    new SimpleHash("MD5", "123456", "323@#@$1234da", 2).toHex();
    new SimpleHash("MD5", "123456", "323@#@$1234da", 3).toBase64();
    // 两参：不加盐
    new SimpleHash("MD5", "123456").toHex();

    new SimpleHash("SHA-256", "123456", "323@#@$1234da", 10).toBase64();
    new SimpleHash("SHA-256", "123456", "323@#@$1234da").toHex();
    new SimpleHash("SHA-256", "123456").toHex();

    new SimpleHash("SM3", "123456", "323@#@$1234da").toHex();
    new SimpleHash("SM3", "123456", "323@#@$1234da", 4).toBase64();
    new SimpleHash("SM3", "123456").toHex();
```

#### 2. 密码哈希（`BCrypt`）

**存储用户口令请使用 `BCrypt`**：自带随机盐、work factor 可调，且 `checkpw` 是恒定时间比较。

```java
    // 密码哈希
    String hashedPassword = BCrypt.hashpw("123456", BCrypt.gensalt());
    System.out.println(hashedPassword);

    // 密码校验
    boolean isPasswordMatch = BCrypt.checkpw("123456", hashedPassword);
    System.out.println(isPasswordMatch);
```

### 2.5.4 监听安全事件
框架内置了安全事件发布器，默认会发布以下事件：
- `LoginSuccessEvent`：登录成功事件
- `LoginFailureEvent`：登录失败事件
- `AuthorizationFailureEvent`：鉴权失败事件

#### 方式一：使用 Spring `@EventListener` 监听（推荐）
框架默认使用 Spring 事件总线发布安全事件，你可以直接监听：

```java
@Component
public class SecurityEventListener {

    @EventListener
    public void onLoginSuccess(org.tinycloud.security.event.LoginSuccessEvent event) {
        System.out.println("登录成功: " + event.getLoginId());
    }

    @EventListener
    public void onLoginFailure(org.tinycloud.security.event.LoginFailureEvent event) {
        System.out.println("登录失败: " + event.getLoginId() + ", reason=" + event.getErrorMessage());
    }

    @EventListener
    public void onAuthorizationFailure(org.tinycloud.security.event.AuthorizationFailureEvent event) {
        System.out.println("鉴权失败: " + event.getLoginId() + ", path=" + event.getRequestPath());
    }
}
```

#### 方式二：自定义 `SecurityEventPublisher`
如果你想把事件发送到消息队列、审计平台或日志系统，可以自定义 `SecurityEventPublisher` Bean。
当项目里存在自定义 Bean 时，会自动覆盖框架默认实现：

```java
@Configuration
public class SecurityEventConfig {

    @Bean
    public SecurityEventPublisher securityEventPublisher() {
        return new SecurityEventPublisher() {
            @Override
            public void publishLoginSuccess(LoginSuccessEvent event) {
                // 例如：发送到MQ或写入审计日志
                System.out.println("[AUDIT] 登录成功: " + event.getLoginId() + ", time=" + event.getTimestamp());
            }

            @Override
            public void publishLoginFailure(LoginFailureEvent event) {
                System.out.println("[AUDIT] 登录失败: " + event.getLoginId() + ", reason=" + event.getErrorMessage());
            }

            @Override
            public void publishAuthorizationFailure(AuthorizationFailureEvent event) {
                System.out.println("[AUDIT] 鉴权失败: " + event.getLoginId() + ", path=" + event.getRequestPath());
            }
        };
    }
}
```

> 提示：你也可以保留默认发布器，再通过 `@EventListener` 监听并转发到外部系统，这样代码更简洁。
