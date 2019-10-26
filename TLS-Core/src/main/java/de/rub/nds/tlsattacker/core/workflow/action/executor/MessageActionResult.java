/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action.executor;

import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class MessageActionResult {

    private final List<AbstractRecord> recordList;

    private final List<ProtocolMessage> messageList;

    private final List<DtlsHandshakeMessageFragment> messageFragmentList;

    private final List<DtlsMessageInformation> messageInformationList;

    public MessageActionResult(List<AbstractRecord> recordList, List<ProtocolMessage> messageList,
            List<DtlsHandshakeMessageFragment> messageFragmentList, List<DtlsMessageInformation> messageInformationList) {
        this.recordList = recordList;
        this.messageList = messageList;
        this.messageFragmentList = messageFragmentList;
        this.messageInformationList = messageInformationList;
    }

    /**
     * Generates an empty MessageActionResult, that is, a result whose list
     * fields are empty.
     */
    public MessageActionResult() {
        this(new LinkedList<AbstractRecord>(), new LinkedList<ProtocolMessage>(),
                new LinkedList<DtlsHandshakeMessageFragment>(), new LinkedList<DtlsMessageInformation>());
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
     * Returns message information corresponding to DTLS messages.
     */
    public List<DtlsMessageInformation> getMessageInformationList() {
        return messageInformationList;
    }

    /**
     * Merger this with other results, forming a new result.
     */
    public MessageActionResult merge(MessageActionResult... other) {
        LinkedList<MessageActionResult> results = new LinkedList<MessageActionResult>(Arrays.asList(other));
        results.add(0, this);
        List<AbstractRecord> recordList = new LinkedList<>();
        List<DtlsHandshakeMessageFragment> messageFragmentList = new LinkedList<>();
        List<DtlsMessageInformation> messageInfoList = new LinkedList<>();
        List<ProtocolMessage> messageList = new LinkedList<>();

        for (MessageActionResult result : results) {
            recordList.addAll(result.getRecordList());
            messageFragmentList.addAll(result.getMessageFragmentList());
            messageInfoList.addAll(result.getMessageInformationList());
            messageList.addAll(result.getMessageList());
        }

        return new MessageActionResult(recordList, messageList, messageFragmentList, messageInfoList);
    }
}
