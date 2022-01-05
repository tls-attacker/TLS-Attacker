/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.crypto.cipher.DecryptionCipher;
import de.rub.nds.tlsattacker.core.crypto.cipher.EncryptionCipher;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class RecordCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * cipher for decryption
     */
    protected DecryptionCipher decryptCipher;
    /**
     * cipher for encryption
     */
    protected EncryptionCipher encryptCipher;
    /**
     * TLS context
     */
    private TlsContext context;
    /**
     * cipher state
     */
    private CipherState state;

    public RecordCipher(TlsContext context, CipherState state) {
        this.context = context;
        this.state = state;
    }

    public abstract void encrypt(Record record) throws CryptoException;

    public abstract void encrypt(BlobRecord record) throws CryptoException;

    public abstract void decrypt(Record record) throws CryptoException;

    public abstract void decrypt(BlobRecord record) throws CryptoException;

    /**
     * This function collects data needed for computing MACs and other authentication tags in CBC/CCM/GCM cipher suites.
     *
     * From the Lucky13 paper: An individual record R (viewed as a byte sequence of length at least zero) is processed
     * as follows. The sender maintains an 8-byte sequence number SQN which is incremented for each record sent, and
     * forms a 5-byte field HDR consisting of a 1-byte type field, a 2-byte version field, and a 2-byte length field. It
     * then calculates a MAC over the bytes SQN || HDR || R.
     *
     * @param  record
     *                         The Record for which the data should be collected
     * @param  protocolVersion
     *                         According to which ProtocolVersion the AdditionalAuthenticationData is collected
     * @return                 The AdditionalAuthenticatedData
     */
    protected final byte[] collectAdditionalAuthenticatedData(Record record, ProtocolVersion protocolVersion) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        try {
            if (protocolVersion.isTLS13()) {
                stream.write(record.getContentType().getValue());
                stream.write(record.getProtocolVersion().getValue());
                if (record.getLength() != null && record.getLength().getValue() != null) {
                    stream.write(
                        ArrayConverter.intToBytes(record.getLength().getValue(), RecordByteLength.RECORD_LENGTH));
                } else {
                    // It may happen that the record does not have a length prepared - in that case we will need to add
                    // the length of the data content
                    // This is mostly interessting for fuzzing
                    stream.write(ArrayConverter.intToBytes(record.getCleanProtocolMessageBytes().getValue().length,
                        RecordByteLength.RECORD_LENGTH));
                }
                return stream.toByteArray();
            } else {
                if (protocolVersion.isDTLS() && record.getEpoch() != null) {
                    stream.write(ArrayConverter.intToBytes(record.getEpoch().getValue().shortValue(),
                        RecordByteLength.DTLS_EPOCH));
                    stream.write(ArrayConverter.longToUint48Bytes(record.getSequenceNumber().getValue().longValue()));
                } else {
                    stream.write(ArrayConverter.longToUint64Bytes(record.getSequenceNumber().getValue().longValue()));
                }

                stream.write(record.getContentType().getValue());
                byte[] version;
                if (!protocolVersion.isSSL()) {
                    version = record.getProtocolVersion().getValue();
                } else {
                    version = new byte[0];
                }
                stream.write(version);
                int length;
                if (record.getComputations().getAuthenticatedNonMetaData() == null
                    || record.getComputations().getAuthenticatedNonMetaData().getOriginalValue() == null) {
                    // This case is required for TLS 1.2 aead encryption
                    length = record.getComputations().getPlainRecordBytes().getValue().length;
                } else {
                    length = record.getComputations().getAuthenticatedNonMetaData().getValue().length;

                }
                stream.write(ArrayConverter.intToBytes(length, RecordByteLength.RECORD_LENGTH));
                return stream.toByteArray();
            }
        } catch (IOException e) {
            throw new WorkflowExecutionException("Could not write data to ByteArrayOutputStream");
        }
    }

    public CipherState getState() {
        return state;
    }

    public void setState(CipherState state) {
        this.state = state;
    }

    public ConnectionEndType getLocalConnectionEndType() {
        return context.getConnection().getLocalConnectionEndType();
    }

    public ConnectionEndType getConnectionEndType() {
        return context.getChooser().getConnectionEndType();
    }

    public Integer getDefaultAdditionalPadding() {
        return context.getConfig().getDefaultAdditionalPadding();
    }

    public ConnectionEndType getTalkingConnectionEndType() {
        return context.getTalkingConnectionEndType();
    }

    public Random getRandom() {
        return context.getRandom();
    }

}
