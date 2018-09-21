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
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import java.util.List;
import java.util.Objects;

public class ResponseFingerprint {

    private final boolean receivedTransportHandlerException;

    private final boolean encryptedAlert;

    private final int numberRecordsReceived;

    private final int numberOfMessageReceived;

    private final List<Class<AbstractRecord>> recordClasses;

    private final List<Class<ProtocolMessage>> messageClasses;

    private final List<ProtocolMessage> messageList;

    private final List<AbstractRecord> recordList;

    private final SocketState socketState;

    public ResponseFingerprint(boolean receivedTransportHandlerException, boolean encryptedAlert,
            int numberRecordsReceived, int numberOfMessageReceived, List<Class<AbstractRecord>> recordClasses,
            List<Class<ProtocolMessage>> messageClasses, List<ProtocolMessage> messageList,
            List<AbstractRecord> recordList, SocketState socketState) {
        this.receivedTransportHandlerException = receivedTransportHandlerException;
        this.encryptedAlert = encryptedAlert;
        this.numberRecordsReceived = numberRecordsReceived;
        this.numberOfMessageReceived = numberOfMessageReceived;
        this.recordClasses = recordClasses;
        this.messageClasses = messageClasses;
        this.messageList = messageList;
        this.recordList = recordList;
        this.socketState = socketState;
    }

    public SocketState getSocketState() {
        return socketState;
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
        StringBuilder recordClasses = new StringBuilder();
        for (Class<AbstractRecord> someClass : this.recordClasses) {
            recordClasses.append(someClass.getSimpleName()).append(",");
        }
        StringBuilder messageClasses = new StringBuilder();
        for (Class<ProtocolMessage> someClass : this.messageClasses) {
            messageClasses.append(someClass.getSimpleName()).append(",");
        }
        StringBuilder messages = new StringBuilder();
        for (ProtocolMessage someMessage : this.messageList) {
            messages.append(someMessage.toCompactString()).append(",");
        }
        StringBuilder records = new StringBuilder();
        for (AbstractRecord someRecord : this.getRecordList()) {
            records.append(someRecord.toString()).append(",");
        }

        return "ResponseFingerprint[" + "Exception=" + receivedTransportHandlerException + ", Encrypted="
                + encryptedAlert + ", #Records=" + numberRecordsReceived + ", #Messages=" + numberOfMessageReceived
                + ", RecordClasses=[" + recordClasses.toString() + "], MessageClasses=[" + messageClasses.toString()
                + "], Messages=[" + messages.toString() + "], Reccords=[" + records.toString() + "], NetworkState="
                + socketState + ']';
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 53 * hash + (this.receivedTransportHandlerException ? 1 : 0);
        hash = 53 * hash + (this.encryptedAlert ? 1 : 0);
        hash = 53 * hash + this.numberRecordsReceived;
        hash = 53 * hash + this.numberOfMessageReceived;
        hash = 53 * hash + Objects.hashCode(this.socketState);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ResponseFingerprint other = (ResponseFingerprint) obj;
        if (this.receivedTransportHandlerException != other.receivedTransportHandlerException) {
            return false;
        }
        if (this.encryptedAlert != other.encryptedAlert) {
            return false;
        }
        if (this.numberRecordsReceived != other.numberRecordsReceived) {
            return false;
        }
        if (this.numberOfMessageReceived != other.numberOfMessageReceived) {
            return false;
        }
        return this.socketState == other.socketState;
    }

}
