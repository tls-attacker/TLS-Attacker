/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.unittest.helper;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceNormalizer;
import de.rub.nds.tlsattacker.core.workflow.filter.Filter;
import de.rub.nds.tlsattacker.core.workflow.filter.FilterFactory;
import de.rub.nds.tlsattacker.core.workflow.filter.FilterType;

/**
 * Normalize and apply default filter to workflow trace.
 * <p>
 * Emulate the normalize and filter procedure a trace goes through during normal
 * program execution.
 */
public class DefaultNormalizeFilter {

    /**
     * Normalized and filtered the given workflow trace.
     * 
     * @param trace
     *            the workflow trace that should be normalized and filtered
     * @param config
     *            the Config used for normalization/filtering
     */
    public static void normalizeAndFilter(WorkflowTrace trace, Config config) {

        WorkflowTrace origTrace = null;
        if (config.isFiltersKeepUserSettings()) {
            origTrace = WorkflowTrace.copy(trace);
        }

        // Normalize and filter defaults
        WorkflowTraceNormalizer normalizer = new WorkflowTraceNormalizer();
        normalizer.normalize(trace, config);
        Filter filter = FilterFactory.createWorkflowTraceFilter(FilterType.DEFAULT, config);
        filter.applyFilter(trace);

        if (config.isFiltersKeepUserSettings()) {
            // Restore user defined connections, if any
            filter.postFilter(trace, origTrace);
        }
    }

    /**
     * Return a normalized and filtered copy of the given workflow trace.
     * <p>
     * This method does not modify the input trace.
     * 
     * @param trace
     *            the workflow trace that should be normalized and filtered
     * @param config
     *            the Config used for normalization/filtering
     * @return a normalized and filtered copy of the input workflow trace
     */
    public static WorkflowTrace getNormalizedAndFilteredCopy(WorkflowTrace trace, Config config) {
        WorkflowTrace filteredTrace = WorkflowTrace.copy(trace);
        normalizeAndFilter(filteredTrace, config);
        return filteredTrace;
    }

    private DefaultNormalizeFilter() {
    }
}
