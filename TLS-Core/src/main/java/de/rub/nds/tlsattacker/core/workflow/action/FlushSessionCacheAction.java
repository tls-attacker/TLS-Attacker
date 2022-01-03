/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import javax.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 *
 */
@XmlRootElement
public class FlushSessionCacheAction extends TlsAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public FlushSessionCacheAction() {
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        LOGGER.info("Reset Connection Cache");
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
