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
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Apply buffered message to the given context.
 *
 * <p>Call adjustContext() for each message in the context. Does not remove the messages from buffer
 * after execution.
 */
@XmlRootElement
public class ApplyBufferedMessagesAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public ApplyBufferedMessagesAction() {}

    public ApplyBufferedMessagesAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext ctx = state.getContext(connectionAlias).getTlsContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }
        List<ProtocolMessage> messages = ctx.getMessageBuffer();
        if (messages.isEmpty()) {
            LOGGER.debug("Empty buffer, no messages to apply");
        } else {
            for (ProtocolMessage msg : messages) {
                LOGGER.debug("Applying buffered " + msg.toCompactString() + " to context " + ctx);
                ProtocolMessageHandler h = msg.getHandler(ctx);
                h.adjustContext(msg);
            }
        }
        setExecuted(true);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public void reset() {
        setExecuted(false);
    }
}
