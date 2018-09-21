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
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.executor.MessageActionResult;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PopAndSendAction extends MessageAction implements SendingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Pop and send message with this index in message buffer.
     */
    Integer index = null;

    public PopAndSendAction() {
        super();
    }

    public PopAndSendAction(String connectionAlias) {
        super(connectionAlias);
    }

    public PopAndSendAction(String connectionAlias, int index) {
        super(connectionAlias);
        this.index = index;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext tlsContext = state.getTlsContext(connectionAlias);

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        LinkedList<ProtocolMessage> messageBuffer = tlsContext.getMessageBuffer();
        if (index != null && index >= 0) {
            if (index >= messageBuffer.size()) {
                throw new WorkflowExecutionException("Index out of bounds, " + "trying to get element " + index
                        + "of message buffer with " + messageBuffer.size() + "elements.");
            }
            messages.add(messageBuffer.get(index));
            messageBuffer.remove(index);
            tlsContext.getRecordBuffer().remove(index);
        } else {
            messages.add(messageBuffer.pop());
            tlsContext.getRecordBuffer().pop();
        }

        String sending = getReadableString(messages);
        if (connectionAlias == null) {
            LOGGER.info("Sending messages: " + sending);
        } else {
            LOGGER.info("Sending messages (" + connectionAlias + "): " + sending);
        }

        try {
            MessageActionResult result = sendMessageHelper.sendMessages(messages, records, tlsContext, false);
            messages = new ArrayList<>(result.getMessageList());
            records = new ArrayList<>(result.getRecordList());
            setExecuted(true);
        } catch (IOException E) {
            LOGGER.debug(E);
            setExecuted(false);
        }
    }

    @Override
    public String toString() {
        return "PopAndSendAction(index: " + index + ")";
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public void setRecords(List<AbstractRecord> records) {
        this.records = records;
    }

    @Override
    public void reset() {
        messages = new LinkedList<>();
        records = new LinkedList<>();
        setExecuted(null);
    }

    @Override
    public List<ProtocolMessage> getSendMessages() {
        return messages;
    }

    @Override
    public List<AbstractRecord> getSendRecords() {
        return records;
    }

}
