/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 *
 */
public class FlushSessionCacheAction extends TlsAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public FlushSessionCacheAction() {
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        LOGGER.info("Resseting Connection Cache");
        state.getTlsContext().getSessionList().clear();
        state.getTlsContext().setClientSessionId(new byte[0]);
        state.getTlsContext().setServerSessionId(new byte[0]);
        setExecuted(true);
    }

    @Override
    public void reset() {
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

}
