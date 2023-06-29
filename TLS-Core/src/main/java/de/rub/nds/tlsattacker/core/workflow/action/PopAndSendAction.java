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
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class PopAndSendAction extends MessageAction implements SendingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    /** Pop and send message with this index in message buffer. */
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
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getContext(connectionAlias).getTlsContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        LinkedList<ProtocolMessage> messageBuffer = tlsContext.getMessageBuffer();
        if (index != null && index >= 0) {
            if (index >= messageBuffer.size()) {
                throw new ActionExecutionException(
                        "Index out of bounds, "
                                + "trying to get element "
                                + index
                                + "of message buffer with "
                                + messageBuffer.size()
                                + "elements.");
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
            send(tlsContext, messages, fragments, records, httpMessages);
            setExecuted(true);
        } catch (IOException e) {
            LOGGER.debug(e);
            setExecuted(getActionOptions().contains(ActionOption.MAY_FAIL));
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
    public void setRecords(List<Record> records) {
        this.records = records;
    }

    @Override
    public void setFragments(List<DtlsHandshakeMessageFragment> fragments) {
        this.fragments = fragments;
    }

    @Override
    public void reset() {
        messages = new LinkedList<>();
        records = new LinkedList<>();
        fragments = new LinkedList<>();
        setExecuted(null);
    }

    @Override
    public List<ProtocolMessage> getSendMessages() {
        return messages;
    }

    @Override
    public List<Record> getSendRecords() {
        return records;
    }

    @Override
    public List<DtlsHandshakeMessageFragment> getSendFragments() {
        return fragments;
    }
}
