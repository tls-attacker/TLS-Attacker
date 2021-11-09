/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
///**
// * TLS-Attacker - A Modular Penetration Testing Framework for TLS
// *
// * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
// *
// * Licensed under Apache License, Version 2.0
// * http://www.apache.org/licenses/LICENSE-2.0.txt
// */
//
//package de.rub.nds.tlsattacker.core.workflow.action.executor;
//
//import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
//import de.rub.nds.tlsattacker.core.record.Record;
//import de.rub.nds.tlsattacker.core.state.TlsContext;
//import java.util.ArrayList;
//import java.util.LinkedList;
//import java.util.List;
//
//public class FakeReceiveMessageHelper extends ReceiveMessageHelper {
//
//    /**
//     * The messageList of the MessageActionResult returned by receiveMessages().
//     */
//    private List<ProtocolMessage> messagesToReturn = new ArrayList<>();
//    /**
//     * The recordList of the MessageActionResult returned by receiveMessages().
//     */
//    private List<Record> recordsToReturn = new ArrayList<>();
//
//    public FakeReceiveMessageHelper() {
//    }
//
//    public FakeReceiveMessageHelper(List<Record> recordsToReturn, List<ProtocolMessage> messagesToReturn) {
//        this.messagesToReturn = messagesToReturn;
//        this.recordsToReturn = recordsToReturn;
//    }
//
//    @Override
//    public MessageActionResult receiveMessages(TlsContext context) {
//        return receiveMessages(new LinkedList<>(), context);
//    }
//
//    @Override
//    public MessageActionResult receiveMessages(List<ProtocolMessage> expectedMessages, TlsContext context) {
//        return new MessageActionResult(recordsToReturn, messagesToReturn, null);
//    }
//
//    public List<ProtocolMessage> getMessagesToReturn() {
//        return messagesToReturn;
//    }
//
//    public void setMessagesToReturn(List<ProtocolMessage> messagesToReturn) {
//        this.messagesToReturn = messagesToReturn;
//    }
//
//    public List<Record> getRecordsToReturn() {
//        return recordsToReturn;
//    }
//
//    public void setRecordsToReturn(List<Record> recordsToReturn) {
//        this.recordsToReturn = recordsToReturn;
//    }
//}
