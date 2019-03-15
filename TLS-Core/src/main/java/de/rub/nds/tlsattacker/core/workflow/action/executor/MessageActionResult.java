/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action.executor;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;

public class MessageActionResult {

    private final List<AbstractRecord> recordList;

    private final List<ProtocolMessage> messageList;

    private final List<ProtocolMessage> messageFragmentList;

    public MessageActionResult(List<AbstractRecord> recordList, List<ProtocolMessage> messageList,
            List<ProtocolMessage> messageFragmentList) {
        this.recordList = recordList;
        this.messageList = messageList;
        this.messageFragmentList = messageFragmentList;
    }

    /**
     * Generates an empty MessageActionResult, that is, a result whose list
     * fields are empty.
     */
    public MessageActionResult() {
        this(new LinkedList<AbstractRecord>(), new LinkedList<ProtocolMessage>(), new LinkedList<ProtocolMessage>());
    }

    public List<AbstractRecord> getRecordList() {
        return recordList;
    }

    public List<ProtocolMessage> getMessageList() {
        return messageList;
    }

    public List<ProtocolMessage> getMessageFragmentList() {
        return messageFragmentList;
    }

    /**
     * Merger this with other results, forming a new result.
     */
    public MessageActionResult merge(MessageActionResult... other) {
        LinkedList<MessageActionResult> results = new LinkedList<MessageActionResult>(Arrays.asList(other));
        results.add(0, this);
        List<AbstractRecord> recordList = new LinkedList<>();
        List<ProtocolMessage> messageFragmentList = new LinkedList<>();
        List<ProtocolMessage> messageList = new LinkedList<>();

        for (MessageActionResult result : results) {
            recordList.addAll(result.getRecordList());
            messageFragmentList.addAll(result.getMessageFragmentList());
            messageList.addAll(result.getMessageList());
        }

        return new MessageActionResult(recordList, messageList, messageFragmentList);
    }
}
