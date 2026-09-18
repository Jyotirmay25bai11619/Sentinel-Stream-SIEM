package com.sentinelstream.concurrency;

import com.sentinelstream.model.TelemetryRecord;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Bounded blocking queue providing thread-safe transfer and backpressure
 * between the telemetry producer and consumer thread pool.
 */
public class SharedLogBuffer {

    /** Sentinel record placed on the queue once per consumer to signal shutdown. */
    public static final TelemetryRecord POISON_PILL =
            new TelemetryRecord(-1, null, "0.0.0.0", "SHUTDOWN", "__POISON_PILL__");

    private final BlockingQueue<TelemetryRecord> queue;

    public SharedLogBuffer(int capacity) {
        this.queue = new LinkedBlockingQueue<>(capacity);
    }

    /** Blocks if the buffer is full -- this is the backpressure mechanism. */
    public void put(TelemetryRecord record) throws InterruptedException {
        queue.put(record);
    }

    /** Blocks if the buffer is empty. */
    public TelemetryRecord take() throws InterruptedException {
        return queue.take();
    }

    public int size() {
        return queue.size();
    }
}
