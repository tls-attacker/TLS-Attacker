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
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ReceiveAsciiAction extends AsciiAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private String receivedAsciiString;

    public ReceiveAsciiAction() {
        super();
    }

    public ReceiveAsciiAction(String asciiText, String encoding) {
        super(asciiText, encoding);
        receivedAsciiString = null;
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
            receivedAsciiString = new String(fetchData, getEncoding());
            LOGGER.info("Received: " + receivedAsciiString);

            setExecuted(true);
        } catch (IOException E) {
            LOGGER.debug(E);
            setExecuted(false);
        }
    }

    public String getReceivedAsciiString() {
        return receivedAsciiString;
    }

    @Override
    public void reset() {
        setExecuted(null);
    }

    @Override
    public boolean executedAsPlanned() {
        return Objects.equals(receivedAsciiString, getAsciiText());
    }
}
