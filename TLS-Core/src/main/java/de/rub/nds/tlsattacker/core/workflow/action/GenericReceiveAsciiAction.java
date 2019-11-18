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
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GenericReceiveAsciiAction extends AsciiAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private GenericReceiveAsciiAction() {
    }

    public GenericReceiveAsciiAction(String encoding) {
        super(encoding);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext tlsContext = state.getTlsContext();

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }
        try {
            LOGGER.debug("Receiving ASCII message...");
            byte[] fetchData = tlsContext.getTransportHandler().fetchData();
            setAsciiText(new String(fetchData, getEncoding()));
            LOGGER.info("Received:" + getAsciiText());
            setExecuted(true);
        } catch (IOException E) {
            LOGGER.debug(E);
            setExecuted(false);
        }
    }

    @Override
    public void reset() {
        setExecuted(null);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

}
