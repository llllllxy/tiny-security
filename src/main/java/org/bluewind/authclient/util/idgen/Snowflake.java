package org.bluewind.authclient.util.idgen;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Random;

/**
 * 雪花算法生成分布式ID
 *
 * @author liuxingyu01
 * @version  2022-05-21 9:53
 **/
public class Snowflake {
    final static Logger log = LoggerFactory.getLogger(Snowflake.class);

    private final static long TWEPOCH = 1288834974657L;

    // 机器标识位数
    private final static long WORKER_ID_BITS = 5L;

    // 数据中心标识位数
    private final static long DATA_CENTER_ID_BITS = 5L;

    // 机器ID最大值 31
    private final static long MAX_WORKER_ID = -1L ^ (-1L << WORKER_ID_BITS);

    // 数据中心ID最大值 31
    private final static long MAX_DATA_CENTER_ID = -1L ^ (-1L << DATA_CENTER_ID_BITS);

    // 毫秒内自增位
    private final static long SEQUENCE_BITS = 12L;

    // 机器ID偏左移12位
    private final static long WORKER_ID_SHIFT = SEQUENCE_BITS;

    private final static long DATA_CENTER_ID_SHIFT = SEQUENCE_BITS + WORKER_ID_BITS;

    // 时间毫秒左移22位
    private final static long TIMESTAMP_LEFT_SHIFT = SEQUENCE_BITS + WORKER_ID_BITS + DATA_CENTER_ID_BITS;

    private final static long SEQUENCE_MASK = -1L ^ (-1L << SEQUENCE_BITS);

    private long lastTimestamp = -1L;

    private long sequence = 0L;
    private final long workerId;
    private final long dataCenterId;

    // 私有化示例要加上volatile，防止jvm重排序，导致空指针
    private static volatile Snowflake snowflake = null;
    private static final Object lock = new Object();

    // 单例禁止new实例化
    private Snowflake(long workerId, long dataCenterId) {
        if (workerId > MAX_WORKER_ID || workerId < 0) {
            workerId = getRandom(MAX_WORKER_ID);
        }
        if (dataCenterId > MAX_DATA_CENTER_ID || dataCenterId < 0) {
            throw new IllegalArgumentException(
                    String.format("%s 数据中心ID最大值 必须是 %d 到 %d 之间", dataCenterId, 0, MAX_DATA_CENTER_ID));
        }
        this.workerId = workerId;
        this.dataCenterId = dataCenterId;
    }

    /**
     * 获取单例（懒汉式单例，有线程安全问题，所以加锁）
     *
     * @return
     */
    public static Snowflake getInstance() {
        if (snowflake == null) {
            synchronized (lock) {
                if (snowflake == null) {
                    long workerId = getRandom(MAX_WORKER_ID);
                    long dataCenterId = getRandom(MAX_DATA_CENTER_ID);

                    snowflake = new Snowflake(workerId, dataCenterId);
                }
            }
        }
        return snowflake;
    }

    /**
     * 生成1-31之间的随机数
     *
     * @return
     */
    private static long getRandom(long maxId) {
        int max = (int) (maxId);
        int min = 1;
        Random random = new Random();
        long result = random.nextInt(max - min) + min;
        return result;
    }

    /**
     * 根据算法，生成下一个ID
     * @return
     */
    private synchronized long generateId() {
        long timestamp = time();
        if (timestamp < lastTimestamp) {
            log.error("时钟向后移动，拒绝生成id " + (lastTimestamp - timestamp) + " milliseconds");
        }
        if (lastTimestamp == timestamp) {
            // 当前毫秒内，则+1
            sequence = (sequence + 1) & SEQUENCE_MASK;
            if (sequence == 0) {
                // 当前毫秒内计数满了，则等待下一秒
                timestamp = tilNextMillis(lastTimestamp);
            }
        } else {
            sequence = 0;
        }
        lastTimestamp = timestamp;

        // ID偏移组合生成最终的ID，并返回ID
        long nextId = ((timestamp - TWEPOCH) << TIMESTAMP_LEFT_SHIFT) | (dataCenterId << DATA_CENTER_ID_SHIFT)
                | (workerId << WORKER_ID_SHIFT) | sequence;

        return nextId;
    }

    private long tilNextMillis(final long lastTimestamp) {
        long timestamp = this.time();
        while (timestamp <= lastTimestamp) {
            timestamp = this.time();
        }
        return timestamp;
    }

    private long time() {
        return System.currentTimeMillis();
    }


    /**
     * 获取雪花算法ID，返回String类型
     *
     * @return
     */
    public static String nextId() {
        return String.valueOf(Snowflake.getInstance().generateId());
    }


    /**
     * 获取雪花算法ID，返回String类型
     *
     * @return
     */
    public static long nextLongId() {
        return Snowflake.getInstance().generateId();
    }


    /**
     * 测试调用
     *
     * @param args
     */
    public static void main(String[] args) {
        long start = System.currentTimeMillis();

        for (int i = 0, len = 10000; i < len; i++) {
            System.out.println(nextId());
        }

        System.out.println("10000耗时: " + (System.currentTimeMillis() - start) + "ms");
    }
}
