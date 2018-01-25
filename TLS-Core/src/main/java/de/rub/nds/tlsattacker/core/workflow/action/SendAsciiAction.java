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
import static de.rub.nds.tlsattacker.core.workflow.action.TlsAction.LOGGER;
import java.io.IOException;

public class SendAsciiAction extends MessageAction {

    private String asciiString;

    public SendAsciiAction(String asciiString) {
        super();
        this.asciiString = asciiString;
    }

    public SendAsciiAction() {
        super();
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException, IOException {
        TlsContext tlsContext = state.getTlsContext();

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        try {
            tlsContext.getTransportHandler().sendData(asciiString.getBytes());
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
        return true;
    }

    public String getAsciiString() {
        return asciiString;
    }

    public void setAsciiString(String asciiString) {
        this.asciiString = asciiString;
    }
}
