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
import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import static de.rub.nds.tlsattacker.tls.workflow.action.TLSAction.LOGGER;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ActionExecutor;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.MessageActionResult;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ReceiveAction extends MessageAction {

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
        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }
        LOGGER.info("Receiving Messages...");
        tlsContext.setTalkingConnectionEnd(tlsContext.getConfig().getMyConnectionPeer());
        MessageActionResult result = executor.receiveMessages(configuredMessages);
        actualRecords.addAll(result.getRecordList());
        actualMessages.addAll(result.getMessageList());
        setExecuted(true);

        String expected = getReadableString(configuredMessages);
        LOGGER.debug("Receive Expected:" + expected);
        String received = getReadableString(actualMessages);
        LOGGER.debug("Receive Actual:" + received);
        LOGGER.info("Received Messages:" + received);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Receive Action:\n");
        sb.append("\tConfigured:");
        for (ProtocolMessage message : configuredMessages) {
            sb.append(message.toCompactString());
            sb.append(", ");
        }
        sb.append("\n\tActual:");
        for (ProtocolMessage message : actualMessages) {
            sb.append(message.toCompactString());
            sb.append(", ");
        }
        return sb.toString();
    }

}
