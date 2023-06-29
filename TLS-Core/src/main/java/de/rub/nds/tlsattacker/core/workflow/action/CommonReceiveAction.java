/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import java.util.List;

public abstract class CommonReceiveAction extends MessageAction {

    public CommonReceiveAction() {
        super();
    }

    public CommonReceiveAction(List<ProtocolMessage> messages) {
        super(messages);
    }

    public CommonReceiveAction(ProtocolMessage... messages) {
        super(messages);
    }

    public CommonReceiveAction(String connectionAlias) {
        super(connectionAlias);
    }

    public CommonReceiveAction(String connectionAlias, List<ProtocolMessage> messages) {
        super(connectionAlias, messages);
    }

    public CommonReceiveAction(String connectionAlias, ProtocolMessage... messages) {
        super(connectionAlias, messages);
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        LOGGER.debug("Receiving Messages...");
        distinctReceive(tlsContext);

        setExecuted(true);

        String expected = getReadableString(getExpectedMessages());
        LOGGER.debug("Receive Expected:" + expected);
        String received = getReadableString(messages);
        if (hasDefaultAlias()) {
            LOGGER.info("Received Messages: " + received);
        } else {
            LOGGER.info("Received Messages (" + getConnectionAlias() + "): " + received);
        }
    }

    protected abstract void distinctReceive(TlsContext tlsContext);

    public abstract List<ProtocolMessage> getExpectedMessages();
}
