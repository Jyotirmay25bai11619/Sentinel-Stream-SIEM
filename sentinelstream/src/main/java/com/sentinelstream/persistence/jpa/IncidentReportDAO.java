package com.sentinelstream.persistence.jpa;

import com.sentinelstream.model.TelemetryRecord;
import com.sentinelstream.rules.SecurityRule;

import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Data access layer for security incidents and threat actor records.
 * Uses short-lived entity managers per operation to support concurrent consumers.
 */
public class IncidentReportDAO {

    private static final Logger LOGGER = Logger.getLogger(IncidentReportDAO.class.getName());
    private static final Map<String, Long> ORIGIN_CACHE = new ConcurrentHashMap<>();
    private static final Object ORIGIN_LOCK = new Object();

    /**
     * Persists an incident finding, linking it to a canonical ThreatOrigin record.
     */
    public void persistIncident(SecurityRule.RuleFinding finding, TelemetryRecord record) {
        EntityManager em = JpaUtil.getEntityManagerFactory().createEntityManager();
        try {
            em.getTransaction().begin();

            ThreatOrigin origin = findOrCreateOrigin(em, finding.getSourceIp(), record.getTimestamp());

            IncidentReport report = new IncidentReport(
                    finding.getRuleName(),
                    finding.getSeverity(),
                    finding.getSummary(),
                    record.getTimestamp(),
                    record.getSequenceId(),
                    origin);

            em.persist(report);
            em.getTransaction().commit();

        } catch (RuntimeException e) {
            if (em.getTransaction().isActive()) {
                em.getTransaction().rollback();
            }
            LOGGER.log(Level.SEVERE, "Failed to persist incident report", e);
        } finally {
            em.close();
        }
    }

    private ThreatOrigin findOrCreateOrigin(EntityManager em, String ip, LocalDateTime seenAt) {
        Long cachedId = ORIGIN_CACHE.get(ip);
        if (cachedId != null) {
            ThreatOrigin origin = em.find(ThreatOrigin.class, cachedId);
            if (origin != null) {
                return origin;
            }
        }

        synchronized (ORIGIN_LOCK) {
            cachedId = ORIGIN_CACHE.get(ip);
            if (cachedId != null) {
                ThreatOrigin origin = em.find(ThreatOrigin.class, cachedId);
                if (origin != null) {
                    return origin;
                }
            }

            EntityManager originEm = JpaUtil.getEntityManagerFactory().createEntityManager();
            try {
                originEm.getTransaction().begin();
                List<ThreatOrigin> existing = originEm.createQuery(
                        "SELECT t FROM ThreatOrigin t WHERE t.ipAddress = :ip", ThreatOrigin.class)
                        .setParameter("ip", ip)
                        .getResultList();

                ThreatOrigin origin;
                if (!existing.isEmpty()) {
                    origin = existing.get(0);
                } else {
                    origin = new ThreatOrigin(ip, seenAt.toString());
                    originEm.persist(origin);
                }
                originEm.getTransaction().commit();
                ORIGIN_CACHE.put(ip, origin.getId());
                return em.find(ThreatOrigin.class, origin.getId());
            } catch (RuntimeException e) {
                if (originEm.getTransaction().isActive()) {
                    originEm.getTransaction().rollback();
                }
                throw e;
            } finally {
                originEm.close();
            }
        }
    }

    /**
     * Queries all incidents ordered by threat severity and timestamp.
     */
    public List<IncidentReport> findAllOrderedBySeverityDescending() {
        EntityManager em = JpaUtil.getEntityManagerFactory().createEntityManager();
        try {
            TypedQuery<IncidentReport> query = em.createQuery(
                    "SELECT i FROM IncidentReport i ORDER BY i.severity DESC, i.detectedAt DESC",
                    IncidentReport.class);
            return query.getResultList();
        } finally {
            em.close();
        }
    }

    /**
     * Queries incidents originating from a specific IP address.
     */
    public List<IncidentReport> findByOriginIp(String ip) {
        EntityManager em = JpaUtil.getEntityManagerFactory().createEntityManager();
        try {
            TypedQuery<IncidentReport> query = em.createQuery(
                    "SELECT i FROM IncidentReport i WHERE i.threatOrigin.ipAddress = :ip " +
                            "ORDER BY i.detectedAt DESC",
                    IncidentReport.class);
            query.setParameter("ip", ip);
            return query.getResultList();
        } finally {
            em.close();
        }
    }
}
