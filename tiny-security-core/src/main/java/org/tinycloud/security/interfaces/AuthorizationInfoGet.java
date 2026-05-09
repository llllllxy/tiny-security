package org.tinycloud.security.interfaces;

import org.tinycloud.security.context.LoginSubject;

import java.util.Set;

/**
 * 自定义权限验证接口扩展，注意权限缓存需要自己控制，框架不处理缓存
 * @author liuxingyu01
 * @version 2023-01-06-9:33
 **/
public interface AuthorizationInfoGet {

    /**
     * 返回一个账号所拥有的权限码集合
     */
    Set<String> getPermissionSet(LoginSubject subject);

    /**
     * 返回一个账号所拥有的角色标识集合 (权限与角色可分开校验)
     */
    Set<String> getRoleSet(LoginSubject subject);
}
