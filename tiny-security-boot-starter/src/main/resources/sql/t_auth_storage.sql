SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS `t_auth_storage`;
CREATE TABLE `t_auth_storage`  (
                                   `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '自增主键',
                                   `created_at` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                                   `updated_at` datetime(0) NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
                                   `credentials` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '凭证',
                                   `login_id` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '用户id',
                                   `login_subject` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '用户信息',
                                   `credentials_expire_time` bigint(20) NOT NULL COMMENT 'credentials过期时间',
                                   PRIMARY KEY (`id`) USING BTREE,
                                   UNIQUE INDEX `t_auth_storage_unique_credentials`(`credentials`) USING BTREE COMMENT 'credentials不可重复',
                                   INDEX `idx_t_auth_storage_login_id` (`login_id`) USING BTREE COMMENT '优化login_id查询/统计性能',
                                   INDEX `idx_t_auth_storage_expire_time` (`credentials_expire_time`) USING BTREE COMMENT '优化过期记录清理性能'
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = Dynamic;

SET FOREIGN_KEY_CHECKS = 1;