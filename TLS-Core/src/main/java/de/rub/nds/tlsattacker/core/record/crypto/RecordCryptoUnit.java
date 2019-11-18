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
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

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
     * @param record
     *            The Record for which the data should be collected
     * @param protocolVersion
     *            According to which ProtocolVersion the
     *            AdditionalAuthenticationData is collected
     * @return The AdditionalAuthenticatedData
     */
    protected final byte[] collectAdditionalAuthenticatedData(Record record, ProtocolVersion protocolVersion) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        try {
            if (protocolVersion == ProtocolVersion.TLS13) {
                stream.write(record.getContentType().getValue());
                stream.write(record.getProtocolVersion().getValue());
                stream.write(ArrayConverter.intToBytes(record.getLength().getValue(), RecordByteLength.RECORD_LENGTH));
                return stream.toByteArray();
            } else {
                if (protocolVersion.isDTLS()) {
                    stream.write(ArrayConverter.intToBytes(record.getEpoch().getValue().shortValue(),
                            RecordByteLength.DTLS_EPOCH));
                    stream.write(ArrayConverter.longToUint48Bytes(record.getComputations().getSequenceNumber()
                            .getValue().longValue()));
                } else {
                    stream.write(ArrayConverter.longToUint64Bytes(record.getComputations().getSequenceNumber()
                            .getValue().longValue()));
                }

                stream.write(record.getContentType().getValue());
                byte[] version;
                if (!protocolVersion.isSSL()) {
                    version = record.getProtocolVersion().getValue();
                } else {
                    version = new byte[0];
                }
                stream.write(version);
                int length = record.getComputations().getNonMetaDataMaced().getValue().length;
                stream.write(ArrayConverter.intToBytes(length, RecordByteLength.RECORD_LENGTH));
                return stream.toByteArray();
            }
        } catch (IOException E) {
            throw new WorkflowExecutionException("Could not write data to ByteArrayOutputStream");
        }
    }
}
