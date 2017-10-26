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
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Strips all record messages.
 */
public class DiscardRecordsFilter extends Filter {

    protected static final Logger LOGGER = LogManager.getLogger(DiscardRecordsFilter.class);

    public DiscardRecordsFilter(Config config) {
        super(config);
    }

    @Override
    public WorkflowTrace filteredCopy(WorkflowTrace trace, Config config) {

        WorkflowTrace filteredTrace = WorkflowTrace.copy(trace);

        for (TlsAction action : filteredTrace.getTlsActions()) {
            if (action.isMessageAction()) {
                ((MessageAction) action).setRecords();
            }
        }

        return filteredTrace;
    }

}
