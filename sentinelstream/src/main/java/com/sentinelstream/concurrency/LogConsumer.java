package com.sentinelstream.concurrency;

import com.sentinelstream.model.TelemetryRecord;
import com.sentinelstream.persistence.jdbc.TelemetryBatchWriter;
import com.sentinelstream.persistence.jpa.IncidentReportDAO;
import com.sentinelstream.rules.RuleLoader;
import com.sentinelstream.rules.SecurityRule;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.logging.Logger;

/**
 * Worker thread that consumes telemetry records from the shared queue,
 * runs active detection rules, and routes events to storage.
 */
public class LogConsumer implements Runnable {

    private static final Logger LOGGER = Logger.getLogger(LogConsumer.class.getName());
    private static final int JDBC_BATCH_SIZE = 500;

    private final int consumerId;
    private final SharedLogBuffer buffer;
    private final TelemetryBatchWriter batchWriter;
    private final IncidentReportDAO incidentDao;
    private final List<SecurityRule> rules;

    private long recordsProcessed = 0;
    private long findingsRaised = 0;

    public LogConsumer(int consumerId, SharedLogBuffer buffer,
                        TelemetryBatchWriter batchWriter, IncidentReportDAO incidentDao) {
        this.consumerId = consumerId;
        this.buffer = buffer;
        this.batchWriter = batchWriter;
        this.incidentDao = incidentDao;
        this.rules = new RuleLoader().loadFreshInstances();
    }

    @Override
    public void run() {
        List<TelemetryRecord> pendingBatch = new ArrayList<>(JDBC_BATCH_SIZE);
        LOGGER.info(() -> "Consumer-" + consumerId + " started with " + rules.size() + " active rules");

        try {
            while (true) {
                TelemetryRecord record = buffer.take();

                if (record == SharedLogBuffer.POISON_PILL) {
                    flushBatch(pendingBatch);
                    LOGGER.info(() -> String.format(
                            "Consumer-%d shutting down: processed=%,d findings=%,d",
                            consumerId, recordsProcessed, findingsRaised));
                    break;
                }

                // Evaluate each configured detection rule
                for (SecurityRule rule : rules) {
                    Optional<SecurityRule.RuleFinding> finding = rule.inspect(record);
                    if (finding.isPresent()) {
                        findingsRaised++;
                        SecurityRule.RuleFinding f = finding.get();
                        LOGGER.warning(f::toString);
                        incidentDao.persistIncident(f, record);
                    }
                }

                pendingBatch.add(record);
                recordsProcessed++;

                if (pendingBatch.size() >= JDBC_BATCH_SIZE) {
                    flushBatch(pendingBatch);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.warning("Consumer-" + consumerId + " interrupted");
        }
    }

    private void flushBatch(List<TelemetryRecord> batch) {
        if (batch.isEmpty()) {
            return;
        }
        batchWriter.writeBatch(batch);
        batch.clear();
    }

    public long getRecordsProcessed() {
        return recordsProcessed;
    }

    public long getFindingsRaised() {
        return findingsRaised;
    }
}
