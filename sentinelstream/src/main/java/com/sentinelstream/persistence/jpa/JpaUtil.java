package com.sentinelstream.persistence.jpa;

import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;

/**
 * Manages the singleton JPA EntityManagerFactory lifecycle.
 */
public final class JpaUtil {

    private static final EntityManagerFactory ENTITY_MANAGER_FACTORY = Persistence
            .createEntityManagerFactory("sentinelStreamPU", 
                com.sentinelstream.config.DatabaseConnectionManager.getInstance().getActiveProperties());

    private JpaUtil() {
    }

    public static EntityManagerFactory getEntityManagerFactory() {
        return ENTITY_MANAGER_FACTORY;
    }

    public static void shutdown() {
        if (ENTITY_MANAGER_FACTORY.isOpen()) {
            ENTITY_MANAGER_FACTORY.close();
        }
    }
}
