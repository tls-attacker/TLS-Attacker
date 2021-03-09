/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.util.response;

import de.rub.nds.tlsattacker.core.record.Record;

/**
 *
 *
 */
public class FingerPrintChecker {

    /**
     *
     * @param  fingerprint1
     * @param  fingerprint2
     * @return
     */
    public static EqualityError checkEquality(ResponseFingerprint fingerprint1, ResponseFingerprint fingerprint2) {
        if (fingerprint1.getMessageList().size() == fingerprint2.getMessageList().size()) {
            for (int i = 0; i < fingerprint1.getMessageList().size(); i++) {
                if (!fingerprint1.getMessageList().get(i).toCompactString()
                    .equals(fingerprint2.getMessageList().get(i).toCompactString())) {
                    if (fingerprint1.getMessageList().get(i).getClass()
                        .equals(fingerprint2.getMessageList().get(i).getClass())) {
                        return EqualityError.MESSAGE_CONTENT;
                    } else {
                        return EqualityError.MESSAGE_CLASS;
                    }
                }
            }
        } else {
            return EqualityError.MESSAGE_COUNT;
        }
        if (fingerprint1.getRecordList() != null && fingerprint2.getRecordList() != null) {
            if (fingerprint1.getRecordList().size() == fingerprint2.getRecordList().size()) {
                for (int i = 0; i < fingerprint1.getRecordList().size(); i++) {
                    if (!fingerprint1.getRecordList().get(i).getClass()
                        .equals(fingerprint2.getRecordList().get(i).getClass())) {
                        return EqualityError.RECORD_CLASS;
                    }
                    // This also finds fragmentation issues
                    if (fingerprint1.getRecordList().get(i).getCompleteRecordBytes().getValue().length
                        != fingerprint2.getRecordList().get(i).getCompleteRecordBytes().getValue().length) {
                        return EqualityError.RECORD_CONTENT;
                    }
                    if (fingerprint1.getRecordList().get(i) instanceof Record
                        && fingerprint2.getRecordList().get(i) instanceof Record) {
                        // Comparing Records
                        Record thisRecord = (Record) fingerprint1.getRecordList().get(i);
                        Record otherRecord = (Record) fingerprint2.getRecordList().get(i);
                        if (thisRecord.getContentMessageType().getValue()
                            != otherRecord.getContentMessageType().getValue()) {
                            return EqualityError.RECORD_CONTENT_TYPE;
                        }

                        if (!java.util.Arrays.equals(thisRecord.getProtocolVersion().getValue(),
                            otherRecord.getProtocolVersion().getValue())) {
                            return EqualityError.RECORD_VERSION;
                        }

                    } else {
                        // Comparing BlobRecords
                        if (java.util.Arrays.equals(
                            fingerprint1.getRecordList().get(i).getCompleteRecordBytes().getValue(),
                            fingerprint2.getRecordList().get(i).getCompleteRecordBytes().getValue())) {
                            return EqualityError.RECORD_CONTENT;
                        }
                    }
                }
            } else {
                return EqualityError.RECORD_COUNT;
            }
        }
        if (fingerprint1.getSocketState() == fingerprint2.getSocketState()) {
            return EqualityError.NONE;
        } else {
            return EqualityError.SOCKET_STATE;
        }
    }

    private FingerPrintChecker() {
    }
}
