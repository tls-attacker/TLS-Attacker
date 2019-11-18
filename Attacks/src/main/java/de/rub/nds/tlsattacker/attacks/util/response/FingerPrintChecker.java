/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.util.response;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import java.util.List;
import org.bouncycastle.util.Arrays;

/**
 *
 *
 */
public class FingerPrintChecker {

    /**
     *
     * @param fingerprint1
     * @param fingerprint2
     * @param canDecryptAlerts
     * @return
     */
    public static EqualityError checkEquality(ResponseFingerprint fingerprint1, ResponseFingerprint fingerprint2,
            boolean canDecryptAlerts) {
        if (fingerprint1.isReceivedTransportHandlerException() != fingerprint2.isReceivedTransportHandlerException()) {
            return EqualityError.SOCKET_EXCEPTION;
        }
        if (fingerprint1.getNumberRecordsReceived() != fingerprint2.getNumberRecordsReceived()) {
            return EqualityError.RECORD_COUNT;
        }
        if (fingerprint1.isEncryptedAlert() != fingerprint2.isEncryptedAlert()) {
            return EqualityError.ENCRYPTED_ALERT;
        }
        if (!checkRecordClassEquality(fingerprint1.getRecordClasses(), fingerprint2.getRecordClasses())) {
            return EqualityError.RECORD_CLASS;
        }
        if (!checkRecordLengthEquality(fingerprint1.getRecordList(), fingerprint2.getRecordList())) {
            return EqualityError.RECORD_LENGTH;
        }
        if (!checkRecordProtocolVersionEquality(fingerprint1.getRecordList(), fingerprint2.getRecordList())) {
            return EqualityError.RECORD_VERSION;
        }
        if (!checkRecordContentTypeEquality(fingerprint1.getRecordList(), fingerprint2.getRecordList())) {
            return EqualityError.RECORD_CONTENT_TYPE;
        }
        if ((!fingerprint1.isEncryptedAlert() && !canDecryptAlerts) || canDecryptAlerts) {
            if (!checkAlertRecordEquality(fingerprint1.getRecordList(), fingerprint2.getRecordList())) {
                return EqualityError.ALERT_RECORD_CONTENT;
            }
            if (!checkAlertMessageEquality(fingerprint1.getRecordList(), fingerprint2.getRecordList())) {
                return EqualityError.ALERT_MESSAGE_CONTENT;
            }
            if (fingerprint1.getNumberOfMessageReceived() != fingerprint2.getNumberOfMessageReceived()) {
                return EqualityError.MESSAGE_COUNT;
            }
            if (!checkMessageClassEquality(fingerprint1.getMessageClasses(), fingerprint2.getMessageClasses())) {
                return EqualityError.MESSAGE_CLASS;
            }
        }
        if (!checkSocketState(fingerprint1, fingerprint2)) {
            return EqualityError.SOCKET_STATE;
        }
        return EqualityError.NONE;

    }

    private static boolean checkRecordClassEquality(List<Class<AbstractRecord>> recordClassList1,
            List<Class<AbstractRecord>> recordClassList2) {
        for (int i = 0; i < recordClassList1.size(); i++) {
            if (recordClassList1.get(i).equals(recordClassList2.get(i))) {
            } else {
                return false;
            }
        }
        return true;
    }

    private static boolean checkMessageClassEquality(List<Class<ProtocolMessage>> messageClassList1,
            List<Class<ProtocolMessage>> messageClassList2) {
        for (int i = 0; i < messageClassList1.size(); i++) {
            if (messageClassList1.get(i).equals(messageClassList2.get(i))) {
            } else {
                return false;
            }
        }
        return true;
    }

    private static boolean checkSocketState(ResponseFingerprint fingerprint1, ResponseFingerprint fingerprint2) {
        return fingerprint1.getSocketState() == fingerprint2.getSocketState();
    }

    private static boolean checkAlertRecordEquality(List<AbstractRecord> recordList1, List<AbstractRecord> recordList2) {
        for (int i = 0; i < recordList1.size(); i++) {
            AbstractRecord abstractRecord1 = recordList1.get(i);
            AbstractRecord abstractRecord2 = recordList2.get(i);
            if (abstractRecord1 instanceof BlobRecord && abstractRecord2 instanceof BlobRecord) {
                if (Arrays.areEqual(abstractRecord1.getCompleteRecordBytes().getValue(), abstractRecord1
                        .getCompleteRecordBytes().getValue())) {
                    continue;
                } else {
                    return false;
                }
            }
            Record record1 = (Record) abstractRecord1;
            Record record2 = (Record) abstractRecord2;
            if (record1.getContentMessageType() == ProtocolMessageType.ALERT) {
                if (record1.getLength().getValue() <= 6) {
                    // The record is probably not encrypted, therefore the
                    // protocol message bytes
                    if (!Arrays.areEqual(record1.getProtocolMessageBytes().getValue(), record2
                            .getProtocolMessageBytes().getValue())) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    private static boolean checkAlertMessageEquality(List<AbstractRecord> recordList1, List<AbstractRecord> recordList2) {
        for (int i = 0; i < recordList1.size(); i++) {
            AbstractRecord abstractRecord1 = recordList1.get(i);
            AbstractRecord abstractRecord2 = recordList2.get(i);
            if (abstractRecord1 instanceof BlobRecord && abstractRecord2 instanceof BlobRecord) {
                if (Arrays.areEqual(abstractRecord1.getCompleteRecordBytes().getValue(), abstractRecord1
                        .getCompleteRecordBytes().getValue())) {
                    continue;
                } else {
                    return false;
                }
            }
            Record record1 = (Record) abstractRecord1;
            Record record2 = (Record) abstractRecord2;

            if (record1.getContentMessageType() == ProtocolMessageType.ALERT) {
                // The record is probably not encrypted, therefore the clean
                // bytes have to be equal
                if (!Arrays.areEqual(record1.getCleanProtocolMessageBytes().getValue(), record2
                        .getCleanProtocolMessageBytes().getValue())) {
                    return false;
                }
            }
        }
        return true;
    }

    private static boolean checkMessageListAlertEquality(List<ProtocolMessage> messageList1,
            List<ProtocolMessage> messageList2) {
        for (int i = 0; i < messageList1.size(); i++) {
            ProtocolMessage protocolMessage1 = messageList1.get(i);
            ProtocolMessage protocolMessage2 = messageList2.get(i);
            if (protocolMessage1 instanceof AlertMessage && protocolMessage2 instanceof AlertMessage) {
                if (((AlertMessage) protocolMessage1).getDescription().getValue() != ((AlertMessage) protocolMessage2)
                        .getDescription().getValue()) {
                    return false;
                }
                if (((AlertMessage) protocolMessage1).getLevel().getValue() != ((AlertMessage) protocolMessage2)
                        .getLevel().getValue()) {
                    return false;
                }
            }
        }
        return true;
    }

    private static boolean checkRecordLengthEquality(List<AbstractRecord> recordList1, List<AbstractRecord> recordList2) {
        for (int i = 0; i < recordList1.size(); i++) {
            AbstractRecord abstractRecord1 = recordList1.get(i);
            AbstractRecord abstractRecord2 = recordList2.get(i);

            if (abstractRecord1.getCompleteRecordBytes().getValue().length != abstractRecord2.getCompleteRecordBytes()
                    .getValue().length) {
                return false;
            }
        }
        return true;
    }

    private static boolean checkRecordProtocolVersionEquality(List<AbstractRecord> recordList1,
            List<AbstractRecord> recordList2) {
        for (int i = 0; i < recordList1.size(); i++) {
            AbstractRecord abstractRecord1 = recordList1.get(i);
            AbstractRecord abstractRecord2 = recordList2.get(i);
            if ((abstractRecord1 instanceof Record && abstractRecord2 instanceof BlobRecord)
                    || (abstractRecord1 instanceof BlobRecord && abstractRecord2 instanceof Record)) {
                return false;
            }
            if (abstractRecord1 instanceof BlobRecord && abstractRecord2 instanceof BlobRecord) {
                continue;
            }
            Record record1 = (Record) abstractRecord1;
            Record record2 = (Record) abstractRecord2;
            if (!Arrays.areEqual(record1.getProtocolVersion().getValue(), record2.getProtocolVersion().getValue())) {
                return false;
            }
        }
        return true;
    }

    private static boolean checkRecordContentTypeEquality(List<AbstractRecord> recordList1,
            List<AbstractRecord> recordList2) {
        for (int i = 0; i < recordList1.size(); i++) {
            AbstractRecord abstractRecord1 = recordList1.get(i);
            AbstractRecord abstractRecord2 = recordList2.get(i);

            if (abstractRecord1 instanceof BlobRecord && abstractRecord2 instanceof BlobRecord) {
                continue;
            }
            Record record1 = (Record) abstractRecord1;
            Record record2 = (Record) abstractRecord2;
            if (record1.getContentType().getValue() != record2.getContentType().getValue()) {
                return false;
            }
        }
        return true;
    }

    public static EqualityError checkSimpleEquality(ResponseFingerprint fingerprint1, ResponseFingerprint fingerprint2,
            boolean canDecryptAlerts) {
        if (fingerprint1.isReceivedTransportHandlerException() != fingerprint2.isReceivedTransportHandlerException()) {
            return EqualityError.SOCKET_EXCEPTION;
        }
        if (fingerprint1.getNumberRecordsReceived() != fingerprint2.getNumberRecordsReceived()) {
            return EqualityError.RECORD_COUNT;
        }
        if (fingerprint1.isEncryptedAlert() != fingerprint2.isEncryptedAlert()) {
            return EqualityError.ENCRYPTED_ALERT;
        }
        if ((!fingerprint1.isEncryptedAlert() && !canDecryptAlerts) || canDecryptAlerts) {
            if (fingerprint1.getNumberOfMessageReceived() != fingerprint2.getNumberOfMessageReceived()) {
                return EqualityError.MESSAGE_COUNT;
            }
            if (!checkMessageListAlertEquality(fingerprint1.getMessageList(), fingerprint2.getMessageList())) {
                return EqualityError.ALERT_MESSAGE_CONTENT;
            }
        }
        if (!checkSocketState(fingerprint1, fingerprint2)) {
            return EqualityError.SOCKET_STATE;
        }
        return EqualityError.NONE;

    }

    private FingerPrintChecker() {
    }
}
