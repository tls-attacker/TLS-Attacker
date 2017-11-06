/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;

/**
 *

 */
public abstract class RecordCryptoUnit {

    protected RecordCipher recordCipher;

    public RecordCryptoUnit(RecordCipher recordCipher) {
        this.recordCipher = recordCipher;
    }

    public RecordCipher getRecordCipher() {
        return recordCipher;
    }

    public void setRecordCipher(RecordCipher recordCipher) {
        this.recordCipher = recordCipher;
    }

    /**
     * This function collects data needed for computing MACs and other
     * authentication tags in CBC/CCM/GCM cipher suites.
     *
     * From the Lucky13 paper: An individual record R (viewed as a byte sequence
     * of length at least zero) is processed as follows. The sender maintains an
     * 8-byte sequence number SQN which is incremented for each record sent, and
     * forms a 5-byte field HDR consisting of a 1-byte type field, a 2-byte
     * version field, and a 2-byte length field. It then calculates a MAC over
     * the bytes SQN || HDR || R.
     *
     * When we are decrypting a ciphertext, the difference between the
     * ciphertext length and plaintext length has to be subtracted from the
     * record length.
     *
     * @param record
     *            The Record for which the data should be collected
     * @param protocolVersion
     *            According to which ProtocolVersion the
     *            AdditionalAuthenticationData is collected
     * @return The AdditionalAuthenticatedData
     */
    protected final byte[] collectAdditionalAuthenticatedData(Record record, ProtocolVersion protocolVersion) {
        byte[] seqNumber = ArrayConverter.longToUint64Bytes(record.getSequenceNumber().getValue().longValue());
        byte[] contentType = { record.getContentType().getValue() };
        int length = record.getNonMetaDataMaced().getValue().length;
        byte[] byteLength = ArrayConverter.intToBytes(length, RecordByteLength.RECORD_LENGTH);
        byte[] version;
        if (!protocolVersion.isSSL()) {
            version = record.getProtocolVersion().getValue();
        } else {
            version = new byte[0];
        }
        byte[] result = ArrayConverter.concatenate(seqNumber, contentType, version, byteLength);
        return result;
    }
}
