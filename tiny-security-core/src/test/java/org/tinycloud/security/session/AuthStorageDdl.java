package org.tinycloud.security.session;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 从**随包发布的** {@code sql/t_auth_storage.sql} 解析出建表语句，并转换为 H2 可执行的 DDL。
 *
 * <p><b>为什么要有这个类（TST-5）</b>：此前 JDBC 测试把建表语句**内联复制**在测试里，
 * 与真实发布的脚本是两份独立维护的 DDL —— 一旦有人改了发布脚本（例如调整列、增删唯一约束），
 * 测试仍然按老结构跑，**测不出任何问题**。例如 {@code credentials} 唯一约束曾经漏掉，
 * 导致凭证碰撞路径长期不可测。这里改为读取**同一份发布文件**，让"测试通过"能代表"发布的 DDL 可用"。
 *
 * <p><b>转换是必要的、也是有边界的</b>：发布脚本是 MySQL 方言（反引号、{@code bigint(20)}、
 * {@code ENGINE=InnoDB}、{@code COLLATE}、{@code COMMENT}），H2 无法直接执行。因此这里只做
 * **方言归一化**，不改动任何结构与语义：
 * <ul>
 *     <li>保留：全部列（名称/类型/是否可空）、主键、唯一索引、普通索引；</li>
 *     <li>丢弃：仅 MySQL 专有的存储/字符集/注释等与结构无关的子句；</li>
 *     <li>{@code SET NAMES} / {@code SET FOREIGN_KEY_CHECKS} 等会话语句不参与建表。</li>
 * </ul>
 * 若转换结果丢失了 {@code credentials} 唯一约束，{@link #statements()} 会直接抛异常 ——
 * 不能让"转换失败"伪装成"测试通过"。
 *
 * @author liuxingyu01
 */
final class AuthStorageDdl {

    /**
     * 发布脚本相对被测模块的位置（测试的工作目录是仓库内的模块目录）。
     */
    private static final String[] CANDIDATE_PATHS = {
            "../tiny-security-boot-starter/src/main/resources/sql/t_auth_storage.sql",
            "tiny-security-boot-starter/src/main/resources/sql/t_auth_storage.sql",
            "src/main/resources/sql/t_auth_storage.sql"
    };

    private static final String TABLE_NAME = "t_auth_storage";

    private AuthStorageDdl() {
    }

    /**
     * 解析并转换发布脚本，返回可在 H2 上依次执行的语句。
     *
     * @return 建表语句（第一条是 DROP，随后是 CREATE TABLE 与索引）
     * @throws IllegalStateException 找不到发布脚本，或转换后缺少关键约束时抛出
     */
    static List<String> statements() {
        String raw = readShippedSql();
        String body = extractCreateTableBody(raw);

        List<String> columns = new ArrayList<>();
        List<String> indexStatements = new ArrayList<>();

        for (String item : splitTopLevel(body)) {
            String definition = normalize(item);
            if (definition.isEmpty()) {
                continue;
            }
            String upper = definition.toUpperCase();
            if (upper.startsWith("PRIMARY KEY")) {
                columns.add(definition);
            } else if (upper.startsWith("UNIQUE INDEX") || upper.startsWith("UNIQUE KEY")) {
                indexStatements.add(toCreateIndex(definition, true));
            } else if (upper.startsWith("INDEX ") || upper.startsWith("KEY ")) {
                indexStatements.add(toCreateIndex(definition, false));
            } else {
                columns.add(definition);
            }
        }

        if (columns.isEmpty()) {
            throw new IllegalStateException("未能从发布的 " + TABLE_NAME + ".sql 解析出任何列，解析逻辑需要更新");
        }

        List<String> statements = new ArrayList<>();
        statements.add("DROP TABLE IF EXISTS " + TABLE_NAME);
        statements.add("CREATE TABLE " + TABLE_NAME + " (\n    " + String.join(",\n    ", columns) + "\n)");
        statements.addAll(indexStatements);

        // 防退化：credentials 唯一约束是凭证碰撞语义的基础（TST-5 记录的漂移事故），必须在场
        boolean hasUniqueCredentials = statements.stream()
                .anyMatch(s -> s.toUpperCase().contains("UNIQUE") && s.contains("credentials"));
        if (!hasUniqueCredentials) {
            throw new IllegalStateException("发布的 " + TABLE_NAME
                    + ".sql 缺少 credentials 唯一约束（或转换时丢失），凭证碰撞将无法被数据库拒绝");
        }
        return statements;
    }

    /**
     * 读取发布脚本；找不到时抛异常而不是静默降级（否则"跳过校验"会被误读成"校验通过"）。
     */
    private static String readShippedSql() {
        for (String candidate : CANDIDATE_PATHS) {
            Path path = Path.of(candidate);
            if (Files.isRegularFile(path)) {
                try {
                    return Files.readString(path, StandardCharsets.UTF_8);
                } catch (IOException e) {
                    throw new IllegalStateException("读取发布 SQL 失败: " + path.toAbsolutePath(), e);
                }
            }
        }
        throw new IllegalStateException("找不到随包发布的 " + TABLE_NAME + ".sql（已尝试: "
                + String.join(", ", CANDIDATE_PATHS) + "）。请在仓库根目录下执行构建，或检查模块结构是否变更。");
    }

    /**
     * 取出 {@code CREATE TABLE ... ( ... );} 的括号内容。
     *
     * <p>这里**不用正则**：`\\((.*?)\\)` 是惰性匹配，会停在列定义里的第一个右括号
     * （如 {@code bigint(20)} 的那个），把表体截断；而贪婪匹配又可能越过表体。
     * 因此改为按括号配对扫描，从 {@code CREATE TABLE t_auth_storage} 后的第一个 {@code (}
     * 开始计数，直到配对的 {@code )} 为止。
     */
    private static String extractCreateTableBody(String sql) {
        Matcher matcher = Pattern.compile(
                "CREATE\\s+TABLE\\s+`?" + TABLE_NAME + "`?\\s*\\(",
                Pattern.CASE_INSENSITIVE).matcher(sql);
        if (!matcher.find()) {
            throw new IllegalStateException("发布脚本中未找到 CREATE TABLE " + TABLE_NAME);
        }
        int openIndex = matcher.end() - 1;
        int depth = 0;
        boolean inQuote = false;
        for (int i = openIndex; i < sql.length(); i++) {
            char c = sql.charAt(i);
            if (c == '\'') {
                inQuote = !inQuote;
            } else if (!inQuote) {
                if (c == '(') {
                    depth++;
                } else if (c == ')') {
                    depth--;
                    if (depth == 0) {
                        return sql.substring(openIndex + 1, i);
                    }
                }
            }
        }
        throw new IllegalStateException("CREATE TABLE " + TABLE_NAME + " 的括号未闭合，发布脚本可能已损坏");
    }

    /**
     * 按顶层逗号切分（忽略括号内的逗号，如 {@code bigint(20)}、{@code COMMENT 'a,b'}）。
     */
    private static List<String> splitTopLevel(String body) {
        List<String> items = new ArrayList<>();
        int depth = 0;
        boolean inQuote = false;
        StringBuilder current = new StringBuilder();
        for (char c : body.toCharArray()) {
            if (c == '\'') {
                inQuote = !inQuote;
            } else if (!inQuote) {
                if (c == '(') {
                    depth++;
                } else if (c == ')') {
                    depth--;
                } else if (c == ',' && depth == 0) {
                    items.add(current.toString());
                    current.setLength(0);
                    continue;
                }
            }
            current.append(c);
        }
        if (current.length() > 0) {
            items.add(current.toString());
        }
        return items;
    }

    /**
     * 去掉 MySQL 专有但 H2 不认的子句：反引号、字符集/排序规则、注释、索引方式、自增起始值。
     */
    private static String normalize(String definition) {
        String result = definition.trim();
        result = result.replace("`", "");
        result = result.replaceAll("(?i)\\s+CHARACTER\\s+SET\\s+\\w+", "");
        result = result.replaceAll("(?i)\\s+COLLATE\\s+\\w+", "");
        result = result.replaceAll("(?i)\\s+COMMENT\\s+'(?:[^']|'')*'", "");
        result = result.replaceAll("(?i)\\s+USING\\s+BTREE", "");
        result = result.replaceAll("(?i)\\s+ON\\s+UPDATE\\s+CURRENT_TIMESTAMP(\\(\\d+\\))?", "");
        result = result.replaceAll("(?i)\\s+AUTO_INCREMENT\\s*=\\s*\\d+", "");
        // bigint(20)/datetime(0)/varchar(256) 之类的长度标注：保留 varchar 的长度，丢弃整型/时间的
        result = result.replaceAll("(?i)\\bbigint\\s*\\(\\s*\\d+\\s*\\)", "BIGINT");
        result = result.replaceAll("(?i)\\bint\\s*\\(\\s*\\d+\\s*\\)", "INT");
        result = result.replaceAll("(?i)\\bdatetime\\s*\\(\\s*\\d+\\s*\\)", "TIMESTAMP");
        result = result.replaceAll("\\s{2,}", " ").trim();
        return result;
    }

    /**
     * 把 MySQL 的 {@code UNIQUE INDEX name(cols)} / {@code INDEX name(cols)} 转成 H2 的
     * {@code CREATE [UNIQUE] INDEX name ON table (cols)}。
     */
    private static String toCreateIndex(String definition, boolean unique) {
        Matcher matcher = Pattern.compile("(?i)(?:UNIQUE\\s+)?(?:INDEX|KEY)\\s+(\\w+)\\s*(\\([^)]*\\))")
                .matcher(definition);
        if (!matcher.find()) {
            throw new IllegalStateException("无法解析索引定义: " + definition);
        }
        String name = matcher.group(1);
        String columns = matcher.group(2);
        return "CREATE " + (unique ? "UNIQUE " : "") + "INDEX " + name + " ON " + TABLE_NAME + " " + columns;
    }
}
