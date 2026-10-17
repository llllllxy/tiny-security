package org.tinycloud.security.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tinycloud.security.exception.TinySecurityException;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Json工具类（基于jackson）
 *
 * @author liuxingyu01
 * @version  2022-03-11-16:47
 **/
public class JsonUtil {

    /**
     * 工具类，禁止实例化。
     */
    private JsonUtil() {
    }

    private final static Logger log = LoggerFactory.getLogger(JsonUtil.class);

    /**
     * 全局 ObjectMapper。
     *
     * <p>1.5.0 起做两件事，都是为了让它能真正承担"会话存 Redis/JDBC"的序列化职责：
     * <ul>
     *     <li>{@code findAndRegisterModules()}：按 classpath 自动注册 Jackson 数据类模块
     *         （JSR-310 / Jdk8 / ParameterNames 等）。此前是裸 {@code new ObjectMapper()}，
     *         {@code extraInfo} 里只要放进 {@code LocalDateTime} 这类 java.time 值，
     *         序列化就会抛 {@code InvalidDefinitionException}，表现为<b>登录直接 500</b>。</li>
     *     <li>关闭 {@code WRITE_DATES_AS_TIMESTAMPS}：让 java.time 值写成 ISO-8601 字符串
     *         （与 Spring Boot 自动配置的 ObjectMapper 行为一致），而不是 {@code [2026,9,30,15,4,5]}
     *         这种数组，便于直接排查 Redis/JDBC 里存的会话内容。</li>
     * </ul>
     *
     * <p>这里用 {@code findAndRegisterModules()} 而不是显式 {@code new JavaTimeModule()}：
     * jsr310 只是 {@code spring-boot-starter-web} 的传递依赖，若使用者把它 exclude 掉，
     * 显式 new 会在类初始化阶段抛 {@code NoClassDefFoundError}，把整个框架一起拖垮；
     * 前者在缺少该模块时只是退回原有行为，不会更糟。
     */
    private final static ObjectMapper objectMapper = new ObjectMapper()
            .findAndRegisterModules()
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);


    /**
     * 对象转JSON字符串
     *
     * <p>序列化失败时抛出 {@link TinySecurityException}（而不是静默返回空串），
     * 避免会话仓储把空串写入 Redis/DB，导致"登录成功但立即失效"的隐蔽故障。
     *
     * @param value 待转换对象
     * @return JSON字符串
     */
    public static String writeValueAsString(Object value) {
        if (value != null) {
            try {
                return objectMapper.writeValueAsString(value);
            } catch (JsonProcessingException e) {
                log.error("JsonUtil -- writeValueAsString -- Exception=", e);
                throw new TinySecurityException("Json serialize failed: " + e.getMessage(), e);
            }
        }
        return "";
    }


    /**
     * JSON字符串转对象
     * @param content JSON字符串
     * @param valueType 类型
     * @param <T> 对象
     * @return  对象
     */
    public static <T> T readValue(String content, Class<T> valueType) {
        if (content != null && !content.trim().isEmpty()) {
            try {
                return objectMapper.readValue(content, valueType);
            } catch (IOException e) {
                if (log.isErrorEnabled()) {
                    log.error("JsonUtil -- readValue -- Exception=", e);
                }
            }
        }

        return null;
    }

    /**
     * JSON字符串转对象
     * @param content JSON字符串
     * @param valueTypeRef TypeReference
     * @param <T> 对象
     * @return 对象
     */
    public static <T> T readValue(String content, TypeReference<T> valueTypeRef) {
        if (content != null && !content.trim().isEmpty()) {
            try {
                return objectMapper.readValue(content, valueTypeRef);
            } catch (IOException e) {
                if (log.isErrorEnabled()) {
                    log.error("JsonUtil -- readValue -- Exception=", e);
                }
            }
        }
        return null;
    }


    /**
     * InputStream文件流转对象
     * @param src 输入流
     * @param valueType  类型
     * @param <T> 对象
     * @return 对象
     */
    public static <T> T readValue(InputStream src, Class<T> valueType) {
        if (src != null) {
            try {
                return objectMapper.readValue(src, valueType);
            } catch (IOException e) {
                if (log.isErrorEnabled()) {
                    log.error("JsonUtil -- readValue -- Exception=", e);
                }
            }
        }
        return null;
    }

    /**
     * JSON字符串转List
     * @param content JSON字符串
     * @param clazz  类型
     * @param <T> 对象
     * @return 对象
     */
    public static <T> List<T> readArrayValue(String content, Class<T> clazz) {
        if (content != null && !content.trim().isEmpty()) {
            try {
                return objectMapper.readValue(content, objectMapper.getTypeFactory().constructParametricType(ArrayList.class, clazz));
            } catch (Exception e) {
                if (log.isErrorEnabled()) {
                    log.error("JsonUtil -- readArrayValue -- Exception=", e);
                }
            }
        }
        return null;
    }

    /**
     * 类型转换
     * @param fromValue 源对象
     * @param toValueType 目标对象类型
     * @param <T> 目标对象
     * @return 目标对象
     */
    public static <T> T convertValue(Object fromValue, Class<T> toValueType) {
        return objectMapper.convertValue(fromValue, toValueType);
    }

}
