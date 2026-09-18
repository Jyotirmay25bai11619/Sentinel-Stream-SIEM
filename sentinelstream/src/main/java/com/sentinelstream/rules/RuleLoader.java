package com.sentinelstream.rules;

import com.sentinelstream.annotation.CriticalAudit;

import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Dynamically discovers and instantiates SecurityRule implementations via reflection.
 * Produces isolated rule instances per consumer thread to avoid shared-state contention.
 */
public class RuleLoader {

    private static final Logger LOGGER = Logger.getLogger(RuleLoader.class.getName());

    private static final String[] DEFAULT_RULE_CLASSES = {
            "com.sentinelstream.rules.BruteForceDetector",
            "com.sentinelstream.rules.DataExfiltrationDetector",
            "com.sentinelstream.rules.SqlInjectionDetector",
            "com.sentinelstream.rules.PathTraversalDetector"
    };

    public List<SecurityRule> loadFreshInstances() {
        List<SecurityRule> rules = new ArrayList<>();

        for (String className : DEFAULT_RULE_CLASSES) {
            try {
                Class<?> clazz = Class.forName(className);

                if (!SecurityRule.class.isAssignableFrom(clazz)) {
                    LOGGER.warning(() -> className + " does not extend SecurityRule, skipping");
                    continue;
                }

                if (clazz.isAnnotationPresent(CriticalAudit.class)) {
                    CriticalAudit audit = clazz.getAnnotation(CriticalAudit.class);
                    LOGGER.info(() -> String.format(
                            "Loading @CriticalAudit rule %s (reason=\"%s\", pageOnCall=%s)",
                            clazz.getSimpleName(), audit.reason(), audit.pageOnCall()));
                }

                Constructor<?> constructor = clazz.getDeclaredConstructor();
                Object instance = constructor.newInstance();
                rules.add((SecurityRule) instance);

            } catch (ClassNotFoundException e) {
                LOGGER.log(Level.SEVERE, "Rule class not found on classpath: " + className, e);
            } catch (ReflectiveOperationException e) {
                LOGGER.log(Level.SEVERE, "Failed to instantiate rule via reflection: " + className, e);
            }
        }

        if (rules.isEmpty()) {
            LOGGER.warning("No security rules were loaded -- pipeline will run in pass-through mode.");
        }

        return rules;
    }

    public static List<String> getConfiguredRuleClassNames() {
        return Arrays.asList(DEFAULT_RULE_CLASSES);
    }
}
