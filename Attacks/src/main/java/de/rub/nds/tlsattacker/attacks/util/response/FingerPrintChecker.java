/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
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
        if (fingerprint1.getMessageList().size() == fingerprint2.getMessageList().size()) {
            for (int i = 0; i < fingerprint1.getMessageList().size(); i++) {
                if (!fingerprint1.getMessageList().get(i).toCompactString()
                        .equals(fingerprint2.getMessageList().get(i).toCompactString())) {
                    if (fingerprint1.getMessageList().get(i).getClass()
                            .equals(fingerprint2.getMessageList().get(i).getClass()))
                        return EqualityError.MESSAGE_CONTENT;
                } else {
                    return EqualityError.MESSAGE_CLASS;
                }
            }
        } else {
            return EqualityError.MESSAGE_COUNT;
        }
        if (fingerprint1.getRecordList().size() == fingerprint2.getRecordList().size()) {
            for (int i = 0; i < fingerprint1.getRecordList().size(); i++) {
                if (!fingerprint1.getRecordList().get(i).getClass()
                        .equals(fingerprint2.getRecordList().get(i).getClass())) {
                    return EqualityError.RECORD_CLASS;
                }
                // This also finds fragmentations issues
                if (fingerprint1.getRecordList().get(i).getCompleteRecordBytes().getValue().length != fingerprint2
                        .getRecordList().get(i).getCompleteRecordBytes().getValue().length) {
                    return EqualityError.RECORD_CONTENT;
                }
                if (fingerprint1.getRecordList().get(i) instanceof Record
                        && fingerprint2.getRecordList().get(i) instanceof Record) {
                    // Comparing Records
                    Record thisRecord = (Record) fingerprint1.getRecordList().get(i);
                    Record otherRecord = (Record) fingerprint2.getRecordList().get(i);
                    if (thisRecord.getContentMessageType().getValue() != otherRecord.getContentMessageType().getValue()) {
                        return EqualityError.RECORD_CONTENT_TYPE;
                    }

                    if (!java.util.Arrays.equals(thisRecord.getProtocolVersion().getValue(), otherRecord
                            .getProtocolVersion().getValue())) {
                        return EqualityError.RECORD_VERSION;
                    }

                } else {
                    // Comparing BlobRecords
                    if (java.util.Arrays.equals(
                            fingerprint1.getRecordList().get(i).getCompleteRecordBytes().getValue(), fingerprint2
                                    .getRecordList().get(i).getCompleteRecordBytes().getValue())) {
                        return EqualityError.RECORD_CONTENT;
                    }
                }
            }
        } else {
            return EqualityError.RECORD_COUNT;
        }
        if (fingerprint1.getSocketState() == fingerprint2.getSocketState()) {
            return EqualityError.NONE;
        } else {
            return EqualityError.SOCKET_STATE;
        }
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

    private FingerPrintChecker() {
    }
}
