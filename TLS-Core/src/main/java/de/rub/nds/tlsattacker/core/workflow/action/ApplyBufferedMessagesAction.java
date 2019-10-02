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
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Apply buffered message to the given context.
 *
 * Call adjustContext() for each message in the context. Does not remove the
 * messages from buffer after execution.
 */
public class ApplyBufferedMessagesAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public ApplyBufferedMessagesAction() {
    }

    public ApplyBufferedMessagesAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext ctx = state.getTlsContext(connectionAlias);

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }
        List<ProtocolMessage> messages = ctx.getMessageBuffer();
        if (messages.isEmpty()) {
            LOGGER.debug("Empty buffer, no messages to apply");
        } else {
            for (ProtocolMessage msg : messages) {
                LOGGER.debug("Applying buffered " + msg.toCompactString() + " to context " + ctx);
                ProtocolMessageHandler h = msg.getHandler(ctx);
                h.adjustTLSContext(msg);
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
