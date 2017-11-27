/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.filter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;

/**
 * Filters workflow trace data for output.
 * 
 * Usually used to clean up workflow traces before serialization.
 * 
 * Note that filtering is unidirectional, i.e. we cannot guarantee that a
 * filtered workflow trace can be loaded to a normalized workflow again.
 */
public abstract class Filter {

    protected final Config config;

    public Filter(Config config) {
        this.config = config;
    }

    /**
     * Get the type of the filter.
     * 
     * @return The type of the filter
     */
    public abstract FilterType getFilterType();

    /**
     * Apply filter to trace.
     * 
     * @param trace
     *            The workflow trace that should be filtered.
     */
    public abstract void applyFilter(WorkflowTrace trace);

    /**
     * Perform some additional steps after filtering, for example restoring user
     * defined values.
     * 
     * @param trace
     *            Apply post filtering to this workflow trace.
     * @param reference
     *            A reference trace that the postFilter can use. This could be a
     *            trace containing original user definitions, for example.
     * 
     */
    public void postFilter(WorkflowTrace trace, WorkflowTrace reference) {
    }
}
