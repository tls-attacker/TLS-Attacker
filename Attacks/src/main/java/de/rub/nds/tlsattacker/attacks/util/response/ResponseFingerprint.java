/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.util.response;

import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.TlsMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 *
 *
 */
public class ResponseFingerprint {

    private final List<ProtocolMessage> messageList;

    private final List<AbstractRecord> recordList;

    private final SocketState socketState;

    /**
     *
     * @param messageList
     * @param recordList
     * @param socketState
     */
    public ResponseFingerprint(List<ProtocolMessage> messageList, List<AbstractRecord> recordList,
        SocketState socketState) {
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
    public List<ProtocolMessage> getMessageList() {
        return messageList;
    }

    /**
     *
     * @return
     */
    @Override
    public String toString() {

        StringBuilder messages = new StringBuilder();
        for (ProtocolMessage someMessage : this.messageList) {
            messages.append(someMessage.toCompactString()).append(",");
        }
        StringBuilder records = new StringBuilder();
        for (AbstractRecord someRecord : this.getRecordList()) {
            records.append(someRecord.getClass().getSimpleName()).append(",");
        }

        return "ResponseFingerprint[ Messages=[" + messages.toString() + "], Records=[" + records.toString()
            + "], SocketState=" + socketState + ']';
    }

    public String toHumanReadable() {
        StringBuilder resultString = new StringBuilder();
        for (ProtocolMessage msg : messageList) {
            if (!(msg instanceof TlsMessage)) {
                resultString.append("{").append(msg.getClass().getName()).append("} ");
                continue;
            }

            TlsMessage message = (TlsMessage) msg;

            switch (message.getProtocolMessageType()) {
                case ALERT:
                    AlertMessage alert = (AlertMessage) message;
                    AlertDescription alertDescription =
                        AlertDescription.getAlertDescription(alert.getDescription().getValue());
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
        if (recordList != null && recordList.size() > 0) {
            resultString.append(" [");
            for (AbstractRecord record : recordList) {
                if (record instanceof Record) {
                    resultString.append("R(" + ((Record) record).getLength().getValue() + "),");
                } else {
                    resultString.append("B(" + ((Record) record).getLength().getValue() + "),");
                }
            }
            // remove last commas
            resultString.deleteCharAt(resultString.length() - 1);
            resultString.append("]");
        }
        resultString.append(" ");
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
                default: // should never occur as all ENUM types are handled
                    throw new UnsupportedOperationException("Unknown Socket State");
            }
        }
        return resultString.toString();
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 29 * hash + Objects.hashCode(this.messageList);
        hash = 29 * hash + Objects.hashCode(this.recordList);
        hash = 29 * hash + Objects.hashCode(this.socketState);
        return hash;
    }

    /**
     *
     * @param  obj
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
        if (this.messageList.size() == other.messageList.size()) {
            for (int i = 0; i < this.messageList.size(); i++) {
                if (!this.messageList.get(i).toCompactString().equals(other.messageList.get(i).toCompactString())) {
                    return false;
                }
            }
        } else {
            return false;
        }
        if (this.recordList != null && other.recordList != null) {
            if (this.recordList.size() == other.recordList.size()) {
                for (int i = 0; i < this.recordList.size(); i++) {
                    if (!this.recordList.get(i).getClass().equals(other.recordList.get(i).getClass())) {
                        return false;
                    }
                    // This also finds fragmentation issues
                    if (this.recordList.get(i).getCompleteRecordBytes().getValue().length
                        != other.recordList.get(i).getCompleteRecordBytes().getValue().length) {
                        return false;
                    }
                    if (this.recordList.get(i) instanceof Record && other.recordList.get(i) instanceof Record) {
                        // Comparing Records
                        Record thisRecord = (Record) this.getRecordList().get(i);
                        Record otherRecord = (Record) other.getRecordList().get(i);
                        if (thisRecord.getContentMessageType().getValue()
                            != otherRecord.getContentMessageType().getValue()) {
                            return false;
                        }

                        if (!Arrays.equals(thisRecord.getProtocolVersion().getValue(),
                            otherRecord.getProtocolVersion().getValue())) {
                            return false;
                        }

                    } else {
                        // Comparing BlobRecords
                        if (!Arrays.equals(this.getRecordList().get(i).getCompleteRecordBytes().getValue(),
                            other.getRecordList().get(i).getCompleteRecordBytes().getValue())) {
                            return false;
                        }
                    }
                }
            } else {
                return false;
            }
        }
        return this.socketState == other.socketState;
    }

    /**
     * //TODO, this does not check record layer compatibility
     *
     * @param  fingerprint
     * @return
     */
    public boolean areCompatible(ResponseFingerprint fingerprint) {
        if (socketState != SocketState.TIMEOUT && fingerprint.getSocketState() != SocketState.TIMEOUT) {
            if (fingerprint.getSocketState() != socketState) {
                return false;
            }
        }
        int minNumberOfMessages = fingerprint.getMessageList().size();
        if (this.messageList.size() < minNumberOfMessages) {
            minNumberOfMessages = this.messageList.size();
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
