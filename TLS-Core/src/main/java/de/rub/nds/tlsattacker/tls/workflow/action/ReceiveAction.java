/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.action;

import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ActionExecutor;
import de.rub.nds.tlsattacker.transport.UDPTransportHandler;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ReceiveAction extends MessageAction {

    private static final Logger LOGGER = LogManager.getLogger(ReceiveAction.class);

    public ReceiveAction() {
        super(new LinkedList<ProtocolMessage>());
    }

    public ReceiveAction(List<ProtocolMessage> messages) {
        super(messages);
    }

    public ReceiveAction(ProtocolMessage message) {
        super(new LinkedList<ProtocolMessage>());
        configuredMessages.add(message);
    }

    @Override
    public void execute(TlsContext tlsContext, ActionExecutor executor) {
        if (executed) {
            throw new WorkflowExecutionException("Action already executed!");
        }
        tlsContext.setTalkingConnectionEnd(tlsContext.getConfig().getMyConnectionPeer());
        actualMessages = executor.receiveMessages(configuredMessages);
        executed = true;
        // TODO can imrove performance while not debugging
        String expected = getReadableString(configuredMessages);
        String received = getReadableString(actualMessages);
        LOGGER.debug("Expected:" + expected);
        LOGGER.debug("Actual:" + received);
    }

    public String getReadableString(List<ProtocolMessage> messages) {
        StringBuilder builder = new StringBuilder();
        for (ProtocolMessage message : messages) {
            builder.append(message.toCompactString());
            if (!message.isRequired()) {
                builder.append("*");
            }
            builder.append(", ");
        }
        return builder.toString();
    }

}
