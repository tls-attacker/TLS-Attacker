/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action.executor;

import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class MessageActionResult {

    private final List<AbstractRecord> recordList;

    private final List<ProtocolMessage> messageList;

    private List<DtlsHandshakeMessageFragment> messageFragmentList;

    public MessageActionResult(List<AbstractRecord> recordList, List<ProtocolMessage> messageList,
        List<DtlsHandshakeMessageFragment> messageFragmentList) {
        this.recordList = recordList;
        this.messageList = messageList;
        this.messageFragmentList = messageFragmentList;
    }

    /**
     * Generates an empty MessageActionResult, that is, a result whose list fields are empty.
     */
    public MessageActionResult() {
        this(new LinkedList<>(), new LinkedList<>(), new LinkedList<>());
    }

    public List<AbstractRecord> getRecordList() {
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
    public void merge(MessageActionResult... other) {

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
    }
}
