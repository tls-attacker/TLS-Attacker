/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action.executor;

import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public class FakeReceiveMessageHelper extends ReceiveMessageHelper {

    /**
     * The messageList of the MessageActionResult returned by receiveMessages().
     */
    private List<ProtocolMessage> messagesToReturn = new ArrayList<>();
    /**
     * The recordList of the MessageActionResult returned by receiveMessages().
     */
    private List<AbstractRecord> recordsToReturn = new ArrayList<>();

    public FakeReceiveMessageHelper() {
    }

    public FakeReceiveMessageHelper(List<AbstractRecord> recordsToReturn, List<ProtocolMessage> messagesToReturn) {
        this.messagesToReturn = messagesToReturn;
        this.recordsToReturn = recordsToReturn;
    }

    @Override
    public MessageActionResult receiveMessages(TlsContext context) {
        return receiveMessages(new LinkedList<ProtocolMessage>(), context);
    }

    @Override
    public MessageActionResult receiveMessages(List<ProtocolMessage> expectedMessages, TlsContext context) {
        return new MessageActionResult(recordsToReturn, messagesToReturn, null, null);
    }

    public List<ProtocolMessage> getMessagesToReturn() {
        return messagesToReturn;
    }

    public void setMessagesToReturn(List<ProtocolMessage> messagesToReturn) {
        this.messagesToReturn = messagesToReturn;
    }

    public List<AbstractRecord> getRecordsToReturn() {
        return recordsToReturn;
    }

    public void setRecordsToReturn(List<AbstractRecord> recordsToReturn) {
        this.recordsToReturn = recordsToReturn;
    }
}
