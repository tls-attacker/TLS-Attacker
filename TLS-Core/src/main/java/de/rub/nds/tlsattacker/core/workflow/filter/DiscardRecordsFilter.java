/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.filter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;

/** Strips all record messages. */
public class DiscardRecordsFilter extends Filter {

    public DiscardRecordsFilter(Config config) {
        super(config);
    }

    /**
     * Apply filter to trace.
     *
     * @param trace The workflow trace that should be filtered.
     */
    @Override
    public void applyFilter(WorkflowTrace trace) {
        for (TlsAction action : trace.getTlsActions()) {
            if (action.isMessageAction()) {
                // ((MessageAction) action).clearRecords(); TODO disabled for now
            }
        }
    }

    @Override
    public FilterType getFilterType() {
        return FilterType.DISCARD_RECORDS;
    }
}
