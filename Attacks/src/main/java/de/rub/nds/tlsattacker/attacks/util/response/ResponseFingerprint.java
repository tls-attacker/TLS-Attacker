/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.util.response;

import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import java.util.List;
import java.util.Objects;

/**
 *
 *
 */
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

    /**
     *
     * @param receivedTransportHandlerException
     * @param encryptedAlert
     * @param numberRecordsReceived
     * @param numberOfMessageReceived
     * @param recordClasses
     * @param messageClasses
     * @param messageList
     * @param recordList
     * @param socketState
     */
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

    /**
     *
     * @return
     */
    public SocketState getSocketState() {
        return socketState;
    }

    /**
     *
     * @return
     */
    public List<AbstractRecord> getRecordList() {
        return recordList;
    }

    /**
     *
     * @return
     */
    public boolean isReceivedTransportHandlerException() {
        return receivedTransportHandlerException;
    }

    /**
     *
     * @return
     */
    public boolean isEncryptedAlert() {
        return encryptedAlert;
    }

    /**
     *
     * @return
     */
    public int getNumberRecordsReceived() {
        return numberRecordsReceived;
    }

    /**
     *
     * @return
     */
    public int getNumberOfMessageReceived() {
        return numberOfMessageReceived;
    }

    /**
     *
     * @return
     */
    public List<Class<AbstractRecord>> getRecordClasses() {
        return recordClasses;
    }

    /**
     *
     * @return
     */
    public List<Class<ProtocolMessage>> getMessageClasses() {
        return messageClasses;
    }

    /**
     *
     * @return
     */
    public List<ProtocolMessage> getMessageList() {
        return messageList;
    }

    /**
     *
     * @return
     */
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
            records.append(someRecord.getClass().getSimpleName()).append(",");
        }

        return "ResponseFingerprint[" + "Exception=" + receivedTransportHandlerException + ", Encrypted="
                + encryptedAlert + ", #Records=" + numberRecordsReceived + ", #Messages=" + numberOfMessageReceived
                + ", RecordClasses=[" + recordClasses.toString() + "], MessageClasses=[" + messageClasses.toString()
                + "], Messages=[" + messages.toString() + "], Reccords=[" + records.toString() + "], NetworkState="
                + socketState + ']';
    }

    public String toHumanReadable() {
        StringBuilder resultString = new StringBuilder();
        for (ProtocolMessage message : messageList) {
            switch (message.getProtocolMessageType()) {
                case ALERT:
                    AlertMessage alert = (AlertMessage) message;
                    AlertDescription alertDescription = AlertDescription.getAlertDescription(alert.getDescription()
                            .getValue());
                    AlertLevel alertLevel = AlertLevel.getAlertLevel(alert.getLevel().getValue());
                    if (alertDescription != null && alertLevel != null && alertLevel != AlertLevel.UNDEFINED) {
                        if (alertLevel == AlertLevel.FATAL) {
                            resultString.append("[").append(alertDescription.name()).append("]");
                        } else {
                            resultString.append("(").append(alertDescription.name()).append(")");
                        }
                    } else {
                        resultString.append("{ALERT-").append(alert.getDescription().getValue()).append("-")
                                .append(alert.getLevel()).append("}");
                    }
                    break;
                case APPLICATION_DATA:
                    resultString.append("{APP}");
                    break;
                case CHANGE_CIPHER_SPEC:
                    resultString.append("{CCS}");
                    break;
                case HANDSHAKE:
                    if (message instanceof FinishedMessage) {
                        resultString.append("{FIN}");
                    } else {
                        resultString.append("{" + message.toCompactString() + "}");
                    }
                    break;
                case HEARTBEAT:
                    resultString.append("{HEARTBEAT}");
                    break;
                case UNKNOWN:
                    resultString.append("{UNKNOWN}");
                    break;
                default:
                    throw new UnsupportedOperationException("Unknown ProtocolMessageType");
            }
            resultString.append(" ");
        }
        if (encryptedAlert) {
            resultString.append(" ENC ");
        }
        if (socketState != null) {
            switch (socketState) {
                case CLOSED:
                    resultString.append("X");
                    break;
                case DATA_AVAILABLE:
                    resultString.append("$$$");
                    break;
                case IO_EXCEPTION:
                    resultString.append("§");
                    break;
                case SOCKET_EXCEPTION:
                    resultString.append("@");
                    break;
                case TIMEOUT:
                    resultString.append("T");
                    break;
                case UP:
                    resultString.append("U");
                    break;
            }
        }
        return resultString.toString();
    }

    /**
     *
     * @return
     */
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

    /**
     *
     * @param obj
     * @return
     */
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
        if (!this.recordClasses.equals(other.recordClasses)) {
            return false;
        }
        if (!this.messageClasses.equals(other.messageClasses)) {
            return false;
        }
        if (this.messageList.size() == other.messageList.size()) {
            for (int i = 0; i < this.messageList.size(); i++) {
                if (!this.messageList.get(i).toCompactString().equals(other.messageList.get(i).toCompactString())) {
                    return false;
                }
            }
        } else {
            return false;
        }
        if (this.numberOfMessageReceived != other.numberOfMessageReceived) {
            return false;
        }
        return this.socketState == other.socketState;
    }

    /**
     * //TODO, this does not check record layer compatibility
     *
     * @param fingerprint
     * @return
     */
    public boolean areCompatible(ResponseFingerprint fingerprint) {
        if (socketState != SocketState.TIMEOUT && fingerprint.getSocketState() != SocketState.TIMEOUT) {
            if (fingerprint.getSocketState() != socketState) {
                return false;
            }
        }
        int minNumberOfMessages = fingerprint.getNumberOfMessageReceived();
        if (getNumberRecordsReceived() < minNumberOfMessages) {
            minNumberOfMessages = this.getNumberRecordsReceived();
        }
        for (int i = 0; i < minNumberOfMessages; i++) {
            ProtocolMessage messageOne = this.getMessageList().get(i);
            ProtocolMessage messageTwo = fingerprint.getMessageList().get(i);
            if (!checkMessagesAreRoughlyEqual(messageOne, messageTwo)) {
                return false;
            }
        }
        return true;

    }

    private boolean checkMessagesAreRoughlyEqual(ProtocolMessage messageOne, ProtocolMessage messageTwo) {
        if (!messageOne.getClass().equals(messageTwo.getClass())) {
            return false;
        }
        if (messageOne instanceof AlertMessage && messageTwo instanceof AlertMessage) {
            // Both are alerts
            AlertMessage alertOne = (AlertMessage) messageOne;
            AlertMessage alertTwo = (AlertMessage) messageTwo;
            if (alertOne.getDescription().getValue() != alertTwo.getDescription().getValue()
                    || alertOne.getLevel().getValue() != alertTwo.getLevel().getValue()) {
                return false;
            }
        }
        // nothing more to check?
        return true;

    }

}
