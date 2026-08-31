package org.tinycloud.security.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
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

    private final static Logger log = LoggerFactory.getLogger(JsonUtil.class);
    private final static ObjectMapper objectMapper = new ObjectMapper();


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
