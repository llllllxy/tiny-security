<h1 align="center">tiny-security</h1>


<p align="center">
	<a target="_blank" href="https://www.apache.org/licenses/LICENSE-2.0">
		<img src="https://img.shields.io/badge/license-Apache%202-green.svg" />
	</a>
	<a target="_blank" href="https://www.oracle.com/technetwork/java/javase/downloads/index.html">
		<img src="https://img.shields.io/badge/JDK-8+-blue.svg" />
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
    <version>1.3.1</version>
</dependency>
```

**SpringBoot 3.x**
```xml
<dependency>
    <groupId>top.lxyccc</groupId>
    <artifactId>tiny-security-boot3-starter</artifactId>
    <version>1.3.1</version>
</dependency>
```

### 2.1.3 配置参数

```yaml
tiny-security:
   # 存储类型，目前支持jdbc和redis和单机内存三种(redis,jdbc,single)，如不配置，则默认为single
   store-type: single
   # token名称 (同时也是cookie名称以适配前后端不分离的模式)
   # 注意：token 依次从 header、URL参数 中读取（开启 enable-cookie 后才会从 cookie 读取）；
   # 通过 URL 参数传递 token 会使其进入访问日志，存在泄露风险，不建议生产环境使用
   token-name: token
   # 会话有效期（会话存储中的subject有效时长），单位秒，默认1800秒(30分钟)
   timeout: 1800
   # 最大登录并发数，默认不限制
   max-concurrent-logins: 2
   # credentials凭证类型，可配置uuid(默认风格)，snowflake(纯数字风格)，objectid(变种uuid)，random128 (随机128位字符串)，nanoid，ulid
   credentials-style: uuid
   # 当配置为jdbc时，存储会话信息的表名字，默认为t_auth_storage
   table-name: t_auth_storage
   # 是否开启权限(角色)校验，默认false不开启，开启后需要实现AuthorizationInfoGet接口
   authorization-enabled: true
   # 是否启用框架默认异常翻译器（自动将框架异常转换为JSON响应），默认true
   exception-translation-enabled: true
   # 是否强制以 HTTP 200 返回异常响应，默认false；开启后异常统一返回200，由响应体 code 字段表达真实错误
   force-http-status-200: false
   # 权限校验方式，可配置ANNOTATION（注解方式）、URL（url方式）
   perm-check-mode: ANNOTATION
   # jwt密钥，强烈建议配置固定的高强度随机值（不配置时框架会生成临时随机密钥，重启后所有会话将失效）
   jwt-secret: your-secret-key-please-replace-me
   # jwt主题，不配置则使用默认值
   jwt-subject: tiny-security
   # jwt自身有效期（秒），默认2592000（即30天）；实际生效值不低于会话timeout，避免token先于会话过期
   jwt-timeout: 2592000
   # 是否启用Cookie模式（登录写cookie、登出清理cookie、从cookie读取token）
   # 默认false纯token模式（前后端分离）；前后端不分离项目需开启
   enable-cookie: false
   # Cookie 是否仅通过 HTTPS 传输，默认false（本地 http 调试友好，生产环境建议开启）
   cookie-secure: false
   # Cookie SameSite 属性，默认LAX（可选 STRICT/LAX/NONE，用于防御 CSRF）
   cookie-same-site: LAX
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
    private final static Logger logger = LoggerFactory.getLogger(PermissionInfoInterfaceImpl.class);


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

也可使用静态工具类 `AuthUtil`：
```java
// （这个方法在无会话时不会抛出异常，而是返回null），还可以直接getLoginIdAsString()， getLoginIdAsInt()， getLoginIdAsLong()
Object loginId = AuthUtil.getLoginId();

// （这个方法在无会话时不会抛出异常，而是返回null）
SecurityContext securityContext = AuthUtil.getSecurityContext();
LoginSubject loginSubject = securityContext == null ? null : securityContext.getLoginSubject();
```

---

### 2.2.4 获取当前登录用户token
```java
@Autowired
private AuthProvider authProvider;

String token = authProvider.getToken();
// 或者
String token = authProvider.getToken(HttpServletRequest);
```
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
authProvider.deleteTokenByLoginId(loginId);

```

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
PermissionInfoInterfaceImpl实现类里返回的权限编码要和接口URL相匹配（需要带上context-path）

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
         return ApiResult.fail(e.getCode(), I18nUtils.getMessage(e.getCode()));
      } else if (e instanceof NoPermissionException) {
         // 无权限异常：使用子类的错误码
         return ApiResult.fail(e.getCode(), I18nUtils.getMessage(e.getCode()));
      } else if (e instanceof ConcurrentLoginOverLimitException) {
         // 并发登录超过最大限制：使用子类的错误码
         return ApiResult.fail(e.getCode(), I18nUtils.getMessage(e.getCode()));
      } else {
         // 兜底：处理 TinySecurityException 其他可能的子类（避免漏判）
         log.warn("未明确处理的 TinySecurityException 子类：{}，错误码：{}", e.getClass().getName(), e.getCode());
         return ApiResult.fail(e.getCode(), I18nUtils.getMessage(e.getCode()));
      }
   }
}
```

---

## 2.5、其他更多用法

### 2.5.1 前端传递token
1. 放在参数里面用`token`传递：
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
}
```

- 配置
```yaml
tiny-security:
  store-type: mongo
```


### 2.5.3 密码哈希与摘要算法
框架封装了一些常见的密码哈希与摘要算法，可供使用（如需对称/非对称加密，推荐直接使用 JDK JCA 或 Hutool、BouncyCastle 等专用密码学库）

1. 摘要算法：
   支持MD5、SHA256和国密SM3算法
```java
    new MD5Hash("123456", "323@#@$1234da", 1).toHex();
    new MD5Hash("123456", "323@#@$1234da").toHex();
    new MD5Hash("123456").toHex();
    new MD5Hash("123456", "323@#@$1234da", 2).toHex();
    new MD5Hash("123456", "323@#@$1234da", 3).toHex();
    new MD5Hash("123456", "323@#@$1234da", 3).toBase64();
    
    new Sha256Hash("123456", "323@#@$1234da", 10).toBase64();
    new Sha256Hash("123456", "323@#@$1234da").toHex();
    new Sha256Hash("123456").toHex();
    new Sha256Hash("123456", "323@#@$1234da", 2).toHex();
    new Sha256Hash("123456", "323@#@$1234da", 3).toHex();
    new Sha256Hash("123456", "323@#@$1234da", 3).toBase64();

    new SM3Hash("123456", "323@#@$1234da", 1).toHex();
    new SM3Hash("123456", "323@#@$1234da").toHex();
    new SM3Hash("123456").toHex();
    new SM3Hash("123456", "323@#@$1234da", 2).toHex();
    new SM3Hash("123456", "323@#@$1234da", 4).toHex();
    new SM3Hash("123456", "323@#@$1234da").toBase64();
```

2. 密码哈希算法
   支持BCrypt算法
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
