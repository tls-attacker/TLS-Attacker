/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.executor;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.record.Record;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class MessageActionResult {

    private final List<Record> recordList;

    private final List<ProtocolMessage> messageList;

    private List<DtlsHandshakeMessageFragment> messageFragmentList;

    public MessageActionResult(
            List<Record> recordList,
            List<ProtocolMessage> messageList,
            List<DtlsHandshakeMessageFragment> messageFragmentList) {
        this.recordList = recordList;
        this.messageList = messageList;
        this.messageFragmentList = messageFragmentList;
    }

    /** Generates an empty MessageActionResult, that is, a result whose list fields are empty. */
    public MessageActionResult() {
        this(new LinkedList<>(), new LinkedList<>(), new LinkedList<>());
    }

    public List<Record> getRecordList() {
        return recordList;
    }

    public List<ProtocolMessage> getMessageList() {
        return messageList;
    }

    public List<DtlsHandshakeMessageFragment> getMessageFragmentList() {
        return messageFragmentList;
    }

    /**
     * Merger this with other results, forming a new result.
     *
     * @param other
     */
    public MessageActionResult merge(MessageActionResult... other) {
        LinkedList<MessageActionResult> results =
                new LinkedList<MessageActionResult>(Arrays.asList(other));
        results.add(0, this);
        List<Record> recordList = new LinkedList<>();
        List<DtlsHandshakeMessageFragment> messageFragmentList = null;
        List<ProtocolMessage> messageList = new LinkedList<>();

        for (MessageActionResult result : other) {
            recordList.addAll(result.getRecordList());
            if (result.getMessageFragmentList() != null) {
                if (messageFragmentList == null) {
                    messageFragmentList = new LinkedList<>();
                }
                messageFragmentList.addAll(result.getMessageFragmentList());
            }
            messageList.addAll(result.getMessageList());
        }
        return new MessageActionResult(recordList, messageList, messageFragmentList);
    }
}
