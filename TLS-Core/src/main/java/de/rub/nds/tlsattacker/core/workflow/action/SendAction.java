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
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.executor.MessageActionResult;
import de.rub.nds.tlsattacker.core.workflow.action.executor.SendMessageHelper;
import java.util.LinkedList;
import java.util.List;

/**
 * todo print configured records
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class SendAction extends MessageAction {

    public SendAction() {
        super(new LinkedList<ProtocolMessage>());
    }

    public SendAction(List<ProtocolMessage> messages) {
        super(messages);
    }

    public SendAction(ProtocolMessage message) {
        super(new LinkedList<ProtocolMessage>());
        configuredMessages.add(message);
    }

    @Override
    public void execute(TlsContext tlsContext) {
        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }
        LOGGER.info("Sending " + getReadableString(configuredMessages));
        MessageActionResult result = SendMessageHelper.sendMessages(configuredMessages, configuredRecords, tlsContext);
        actualMessages.addAll(result.getMessageList());
        actualRecords.addAll(result.getRecordList());

        String expected = getReadableString(configuredMessages);
        LOGGER.debug("Send Expected:" + expected);
        String received = getReadableString(actualMessages);
        LOGGER.debug("Send Actual:" + received);
        setExecuted(true);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Send Action:\n");
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
