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
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.state.State;
import static de.rub.nds.tlsattacker.core.workflow.action.TLSAction.LOGGER;
import de.rub.nds.tlsattacker.core.workflow.action.executor.MessageActionResult;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ReceiveMessageHelper;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class GenericReceiveAction extends MessageAction implements ReceivingAction {

    public GenericReceiveAction() {
        super();
        records = new LinkedList<>();
    }

    @Override
    public void execute(State state) {
        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }
        LOGGER.debug("Receiving Messages...");
        MessageActionResult result = ReceiveMessageHelper.receiveMessages(state.getTlsContext(contextAlias));
        records.addAll(result.getRecordList());
        messages.addAll(result.getMessageList());
        setExecuted(true);
        String received = getReadableString(messages);
        LOGGER.info("Received Messages:" + received);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Receive Action:\n");
        sb.append("\tActual:");
        for (ProtocolMessage message : messages) {
            sb.append(message.toCompactString());
            sb.append(", ");
        }
        return sb.toString();
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public void reset() {
        messages = new LinkedList<>();
        records = new LinkedList<>();
        setExecuted(Boolean.FALSE);
    }

    @Override
    public List<ProtocolMessage> getReceivedMessages() {
        return messages;
    }

    @Override
    public List<AbstractRecord> getReceivedRecords() {
        return records;
    }
}
