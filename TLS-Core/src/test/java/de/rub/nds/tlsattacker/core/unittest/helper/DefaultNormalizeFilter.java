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
 * Normalize and apply default filter to workflow trace. This helper emulates
 * what happens during normal program execution to the trace. That is, it is
 * normalized before execution and default values are filtered before
 * serialization.
 */
public class DefaultNormalizeFilter {

    public static WorkflowTrace normalizeAndFilter(WorkflowTrace trace, Config config) {

        WorkflowTrace origTrace = WorkflowTrace.copy(trace);

        // Normalize and filter defaults
        WorkflowTraceNormalizer normalizer = new WorkflowTraceNormalizer();
        normalizer.normalize(trace, config);
        Filter filter = FilterFactory.createWorkflowTraceFilter(FilterType.DEFAULT, config);
        WorkflowTrace filteredTrace = filter.filteredCopy(trace, config);

        // Restore the original connections
        filteredTrace.setConnections(origTrace.getConnections());

        return filteredTrace;
    }
}
