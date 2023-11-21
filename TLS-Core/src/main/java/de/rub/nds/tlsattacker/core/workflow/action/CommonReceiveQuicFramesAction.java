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
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.state.State;
import java.util.List;

public abstract class CommonReceiveQuicFramesAction extends MessageAction {

    public CommonReceiveQuicFramesAction() {
        super();
    }

    public CommonReceiveQuicFramesAction(List<ProtocolMessage> messages) {
        super(messages);
    }

    public CommonReceiveQuicFramesAction(ProtocolMessage... messages) {
        super(messages);
    }

    public CommonReceiveQuicFramesAction(String connectionAlias) {
        super(connectionAlias);
    }

    public CommonReceiveQuicFramesAction(String connectionAlias, List<ProtocolMessage> messages) {
        super(connectionAlias, messages);
    }

    public CommonReceiveQuicFramesAction(String connectionAlias, ProtocolMessage... messages) {
        super(connectionAlias, messages);
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        LOGGER.debug("Receiving Frames...");
        distinctReceive(tlsContext);

        setExecuted(true);

        String expected = getReadableStringFromQuicFrames(getExpectedQuicFrames());
        LOGGER.debug("Receive Expected: {}", expected);
        String received = getReadableStringFromQuicFrames(quicFrames);
        if (hasDefaultAlias()) {
            LOGGER.info("Received Messages: {}", received);
        } else {
            LOGGER.info("Received Messages ({}): {}", getConnectionAlias(), received);
        }
    }

    protected abstract void distinctReceive(TlsContext tlsContext);

    public abstract List<QuicFrame> getExpectedQuicFrames();
}
