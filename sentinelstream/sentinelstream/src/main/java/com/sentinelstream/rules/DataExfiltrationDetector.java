package com.sentinelstream.rules;

import com.sentinelstream.annotation.CriticalAudit;
import com.sentinelstream.model.TelemetryRecord;
import com.sentinelstream.model.ThreatLevel;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Detects rapid data exfiltration attempts.
 * Monitors high-frequency file access and data transfer events within a short time window per IP.
 */
@CriticalAudit(reason = "Detects rapid data exfiltration bursts", pageOnCall = true)
public class DataExfiltrationDetector extends SecurityRule {

    private static final int EVENT_THRESHOLD = 20;
    private static final Duration WINDOW = Duration.ofSeconds(30);

    private final Map<String, WindowState> stateByIp = new HashMap<>();

    public DataExfiltrationDetector() {
        super("DataExfiltrationDetector", ThreatLevel.CRITICAL);
    }

    @Override
    public Optional<RuleFinding> inspect(TelemetryRecord record) {
        String type = record.getEventType();
        if (!"DATA_TRANSFER".equals(type) && !"FILE_ACCESS".equals(type)) {
            return Optional.empty();
        }

        String ip = record.getSourceIp();
        WindowState state = stateByIp.computeIfAbsent(ip, k -> new WindowState(record.getTimestamp()));

        if (Duration.between(state.windowStart, record.getTimestamp()).compareTo(WINDOW) > 0) {
            // Window expired -- start a fresh count for this IP.
            state.windowStart = record.getTimestamp();
            state.count = 0;
        }

        state.count++;

        if (state.count >= EVENT_THRESHOLD) {
            String summary = String.format("%d file/transfer events within %d seconds",
                    state.count, WINDOW.getSeconds());
            state.count = 0; // reset to avoid re-firing on every event past the threshold
            return Optional.of(new RuleFinding(getRuleName(), getBaseSeverity(), ip, summary));
        }

        return Optional.empty();
    }

    private static final class WindowState {
        LocalDateTime windowStart;
        int count = 0;

        WindowState(LocalDateTime start) {
            this.windowStart = start;
        }
    }
}
