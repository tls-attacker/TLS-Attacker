/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.util.response;

import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import java.util.List;

public class ResponseFingerprint {

    private final boolean receivedTransportHandlerException;

    private final boolean encryptedAlert;

    private final int numberRecordsReceived;

    private final int numberOfMessageReceived;

    private final List<Class<AbstractRecord>> recordClasses;

    private final List<Class<ProtocolMessage>> messageClasses;

    private final List<ProtocolMessage> messageList;

    private final List<AbstractRecord> recordList;

    public ResponseFingerprint(boolean receivedTransportHandlerException, boolean encryptedAlert,
            int numberRecordsReceived, int numberOfMessageReceived, List<Class<AbstractRecord>> recordClasses,
            List<Class<ProtocolMessage>> messageClasses, List<ProtocolMessage> messageList,
            List<AbstractRecord> recordList) {
        this.receivedTransportHandlerException = receivedTransportHandlerException;
        this.encryptedAlert = encryptedAlert;
        this.numberRecordsReceived = numberRecordsReceived;
        this.numberOfMessageReceived = numberOfMessageReceived;
        this.recordClasses = recordClasses;
        this.messageClasses = messageClasses;
        this.messageList = messageList;
        this.recordList = recordList;
    }

    public List<AbstractRecord> getRecordList() {
        return recordList;
    }

    public boolean isReceivedTransportHandlerException() {
        return receivedTransportHandlerException;
    }

    public boolean isEncryptedAlert() {
        return encryptedAlert;
    }

    public int getNumberRecordsReceived() {
        return numberRecordsReceived;
    }

    public int getNumberOfMessageReceived() {
        return numberOfMessageReceived;
    }

    public List<Class<AbstractRecord>> getRecordClasses() {
        return recordClasses;
    }

    public List<Class<ProtocolMessage>> getMessageClasses() {
        return messageClasses;
    }

    public List<ProtocolMessage> getMessageList() {
        return messageList;
    }

    @Override
    public String toString() {
        return "ResponseFingerprint{" + "receivedTransportHandlerException=" + receivedTransportHandlerException
                + ", encryptedAlert=" + encryptedAlert + ", numberRecordsReceived=" + numberRecordsReceived
                + ", numberOfMessageReceived=" + numberOfMessageReceived + ", recordClasses=" + recordClasses
                + ", messageClasses=" + messageClasses + ", messageList=" + messageList + ", recordList=" + recordList
                + '}';
    }

}
