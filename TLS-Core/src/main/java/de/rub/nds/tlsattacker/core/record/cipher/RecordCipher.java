/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.exception.CryptoException;
import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.crypto.cipher.BaseCipher;
import de.rub.nds.tlsattacker.core.crypto.cipher.DecryptionCipher;
import de.rub.nds.tlsattacker.core.crypto.cipher.EncryptionCipher;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class RecordCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final byte[] SEQUENCE_NUMBER_PLACEHOLDER =
            new byte[] {
                (byte) 0xFF,
                (byte) 0xFF,
                (byte) 0xFF,
                (byte) 0xFF,
                (byte) 0xFF,
                (byte) 0xFF,
                (byte) 0xFF,
                (byte) 0xFF
            };

    /** cipher for decryption */
    protected DecryptionCipher decryptCipher;

    /** cipher for encryption */
    protected EncryptionCipher encryptCipher;

    /** TLS context */
    protected TlsContext tlsContext;

    /** cipher state */
    private CipherState state;

    public RecordCipher(TlsContext tlsContext, CipherState state) {
        this.tlsContext = tlsContext;
        this.state = state;
    }

    public abstract void encrypt(Record record) throws CryptoException;

    public abstract void decrypt(Record record) throws CryptoException;

    public void encryptDtls13SequenceNumber(Record record) {
        int length =
                tlsContext.getConfig().getUseDtls13HeaderSeqNumSizeLongEncoding()
                        ? RecordByteLength.DTLS13_CIPHERTEXT_SEQUENCE_NUMBER_LONG
                        : RecordByteLength.DTLS13_CIPHERTEXT_SEQUENCE_NUMBER_SHORT;

        byte[] sequenceNumber = record.getSequenceNumber().getValue().toByteArray();
        if (sequenceNumber.length < 2) {
            // Ensure the sequence number is at least two bytes long. If it is shorter, pad with a
            // leading zero.
            sequenceNumber = new byte[] {0, sequenceNumber[0]};
        }
        if (sequenceNumber.length < length) {
            sequenceNumber = Arrays.copyOf(sequenceNumber, length);
        }

        byte[] mask;
        if (getState().getKeySet() == null) {
            mask = new byte[length];
            LOGGER.warn(
                    "No keys available for DTLS 1.3 mask derivation for sequence number encryption. Using null encryption.");
        } else {
            try {
                mask =
                        ((BaseCipher) encryptCipher)
                                .getDtls13Mask(
                                        getState()
                                                .getKeySet()
                                                .getWriteSnKey(getLocalConnectionEndType()),
                                        record.getProtocolMessageBytes().getValue());
                if (mask.length < length) {
                    mask = Arrays.copyOf(mask, length);
                    LOGGER.warn(
                            "DTLS 1.3 mask does not have enough bytes for encrypting the sequence number. Padding it to the required length with zero bytes.");
                }
            } catch (CryptoException ex) {
                LOGGER.warn("Failed to generate DTLS 1.3 mask. Generating a zero‑byte mask.");
                mask = new byte[length];
            }
        }

        byte[] encryptedSequenceNumber = new byte[length];
        for (int i = 0; i < length; i++) {
            encryptedSequenceNumber[i] = (byte) (sequenceNumber[i] ^ mask[i]);
        }
        record.setEncryptedSequenceNumber(encryptedSequenceNumber);
        LOGGER.debug(
                "Encrypted Sequence Number: {}", record.getEncryptedSequenceNumber().getValue());
    }

    public void decryptDtls13SequenceNumber(Record record) {
        byte[] encryptedSequenceNumber = record.getEncryptedSequenceNumber().getValue();
        byte[] mask;

        try {
            mask =
                    ((BaseCipher) decryptCipher)
                            .getDtls13Mask(
                                    getState()
                                            .getKeySet()
                                            .getReadSnKey(getLocalConnectionEndType()),
                                    record.getProtocolMessageBytes().getValue());
            if (mask.length < encryptedSequenceNumber.length) {
                LOGGER.warn(
                        "DTLS 1.3 mask does not have enough bytes for decrypting the sequence number. Padding it to the required length with zero bytes.");
                mask = Arrays.copyOf(mask, encryptedSequenceNumber.length);
            }
        } catch (CryptoException ex) {
            LOGGER.warn("Failed to generate DTLS 1.3 mask. Generating a zero‑byte mask.");
            mask = new byte[encryptedSequenceNumber.length];
        }

        byte[] sequenceNumber = new byte[encryptedSequenceNumber.length];
        for (int i = 0; i < sequenceNumber.length; i++) {
            sequenceNumber[i] = (byte) (encryptedSequenceNumber[i] ^ mask[i]);
        }

        record.setSequenceNumber(new BigInteger(1, sequenceNumber));
        LOGGER.debug("Decrypted Sequence Number: {}", record.getSequenceNumber().getValue());
    }

    /**
     * This function collects data needed for computing MACs and other authentication tags in
     * CBC/CCM/GCM cipher suites.
     *
     * <p>From the Lucky13 paper: An individual record R (viewed as a byte sequence of length at
     * least zero) is processed as follows. The sender maintains an 8-byte sequence number SQN which
     * is incremented for each record sent, and forms a 5-byte field HDR consisting of a 1-byte type
     * field, a 2-byte version field, and a 2-byte length field. It then calculates a MAC over the
     * bytes SQN || HDR || R.
     *
     * @param record The Record for which the data should be collected
     * @param protocolVersion According to which ProtocolVersion the AdditionalAuthenticationData is
     *     collected
     * @return The AdditionalAuthenticatedData
     */
    protected final byte[] collectAdditionalAuthenticatedData(
            Record record, ProtocolVersion protocolVersion) {
        SilentByteArrayOutputStream stream = new SilentByteArrayOutputStream();
        // TLS 1.3
        if (protocolVersion.isTLS13()) {
            stream.write(record.getContentType().getValue());
            stream.write(record.getProtocolVersion().getValue());
            if (record.getLength() != null && record.getLength().getValue() != null) {
                stream.write(
                        DataConverter.intToBytes(
                                record.getLength().getValue(), RecordByteLength.RECORD_LENGTH));
            } else {
                // It may happen that the record does not have a length prepared - in that case
                // we will need to add
                // the length of the data content
                // This is mostly interesting for fuzzing
                stream.write(
                        DataConverter.intToBytes(
                                record.getCleanProtocolMessageBytes().getValue().length,
                                RecordByteLength.RECORD_LENGTH));
            }
            return stream.toByteArray();
            // DTLS 1.3
        } else if (protocolVersion.isDTLS13()) {
            // Adding the first byte of the unified header
            byte firstByte = record.getUnifiedHeader().getValue();
            stream.write(firstByte);
            // Adding the connection id if present
            if (record.isUnifiedHeaderCidPresent()) {
                stream.write(record.getConnectionId().getValue());
            }
            // Adding the sequence number
            byte[] sequenceNumberBytes =
                    DataConverter.longToUint48Bytes(
                            record.getSequenceNumber().getValue().longValue());
            if (record.isUnifiedHeaderSqnLong()) {
                stream.write(
                        sequenceNumberBytes,
                        sequenceNumberBytes.length
                                - RecordByteLength.DTLS13_CIPHERTEXT_SEQUENCE_NUMBER_LONG,
                        RecordByteLength.DTLS13_CIPHERTEXT_SEQUENCE_NUMBER_LONG);
            } else {
                stream.write(
                        sequenceNumberBytes,
                        sequenceNumberBytes.length
                                - RecordByteLength.DTLS13_CIPHERTEXT_SEQUENCE_NUMBER_SHORT,
                        RecordByteLength.DTLS13_CIPHERTEXT_SEQUENCE_NUMBER_SHORT);
            }
            // Adding the length if present
            if (record.isUnifiedHeaderLengthPresent()) {
                if (record.getLength() != null && record.getLength().getValue() != null) {
                    stream.write(
                            DataConverter.intToBytes(
                                    record.getLength().getValue(), RecordByteLength.RECORD_LENGTH));
                } else {
                    stream.write(
                            DataConverter.intToBytes(
                                    record.getCleanProtocolMessageBytes().getValue().length,
                                    RecordByteLength.RECORD_LENGTH));
                }
            }
            return stream.toByteArray();
            // Other
        } else {
            if (protocolVersion.isDTLS()) {
                if (ProtocolMessageType.getContentType(record.getContentType().getValue())
                        == ProtocolMessageType.TLS12_CID) {
                    stream.write(SEQUENCE_NUMBER_PLACEHOLDER);
                    stream.write(ProtocolMessageType.TLS12_CID.getValue());
                    stream.write(record.getConnectionId().getValue().length);
                } else {
                    stream.write(
                            DataConverter.intToBytes(
                                    record.getEpoch().getValue().shortValue(),
                                    RecordByteLength.DTLS_EPOCH));
                    stream.write(
                            DataConverter.longToUint48Bytes(
                                    record.getSequenceNumber().getValue().longValue()));
                }
            } else {
                stream.write(
                        DataConverter.longToUint64Bytes(
                                record.getSequenceNumber().getValue().longValue()));
            }
            stream.write(record.getContentType().getValue());
            byte[] version;
            if (!protocolVersion.isSSL()) {
                version = record.getProtocolVersion().getValue();
            } else {
                version = new byte[0];
            }
            stream.write(version);
            if (protocolVersion.isDTLS()
                    && ProtocolMessageType.getContentType(record.getContentType().getValue())
                            == ProtocolMessageType.TLS12_CID) {
                stream.write(
                        DataConverter.intToBytes(
                                record.getEpoch().getValue().shortValue(),
                                RecordByteLength.DTLS_EPOCH));
                stream.write(
                        DataConverter.longToUint48Bytes(
                                record.getSequenceNumber().getValue().longValue()));
                stream.write(record.getConnectionId().getValue());
            }
            int length;
            if (record.getComputations().getAuthenticatedNonMetaData() == null
                    || record.getComputations().getAuthenticatedNonMetaData().getOriginalValue()
                            == null) {
                // This case is required for TLS 1.2 aead encryption
                length = record.getComputations().getPlainRecordBytes().getValue().length;
            } else {
                length = record.getComputations().getAuthenticatedNonMetaData().getValue().length;
            }
            stream.write(DataConverter.intToBytes(length, RecordByteLength.RECORD_LENGTH));
            return stream.toByteArray();
        }
    }

    /**
     * Reads a byte array from the end, and counts how many 0x00 bytes there are, until the first
     * non-zero byte appears
     *
     * @param plainRecordBytes the byte array to count from
     * @return number of trailing 0x00 bytes
     */
    private int countTrailingZeroBytes(byte[] plainRecordBytes) {
        int counter = 0;
        for (int i = plainRecordBytes.length - 1; i < plainRecordBytes.length; i--) {
            if (plainRecordBytes[i] == 0) {
                counter++;
            } else {
                return counter;
            }
        }
        return counter;
    }

    /**
     * Encapsulate plain record bytes as TLS 1.3 application data or DTLS 1.2 ConnectionID data
     * container. Construction: CleanBytes | ContentType | 0x00000... (Padding)
     *
     * @param record the record which is affected
     * @return the encapsulated data
     */
    protected byte[] encapsulateRecordBytes(Record record) {
        byte[] padding =
                record.getComputations().getPadding() != null
                        ? record.getComputations().getPadding().getValue()
                        : new byte[0];
        return DataConverter.concatenate(
                record.getCleanProtocolMessageBytes().getValue(),
                new byte[] {record.getContentType().getValue()},
                padding);
    }

    /**
     * Read plain record bytes that are encapsuled as either TLS 1.3 application data or DTLS 1.2
     * ConnectionID data. Construction: CleanBytes | ContentType | 0x00000... (Padding)
     *
     * @param plainRecordBytes the plain encapsulated record bytes
     * @param record the record which is affected
     */
    protected void parseEncapsulatedRecordBytes(byte[] plainRecordBytes, Record record) {
        int numberOfPaddingBytes = countTrailingZeroBytes(plainRecordBytes);
        if (numberOfPaddingBytes == plainRecordBytes.length) {
            LOGGER.warn(
                    "Record contains ONLY padding and no content type. Setting clean bytes == plainbytes");
            record.setCleanProtocolMessageBytes(plainRecordBytes);
            return;
        }
        PlaintextParser parser = new PlaintextParser(plainRecordBytes);
        byte[] cleanBytes =
                parser.parseByteArrayField(plainRecordBytes.length - numberOfPaddingBytes - 1);
        byte[] contentType = parser.parseByteArrayField(1);
        byte[] padding = parser.parseByteArrayField(numberOfPaddingBytes);
        record.getComputations().setPadding(padding);
        record.setCleanProtocolMessageBytes(cleanBytes);
        record.setContentType(contentType[0]);
        record.setContentMessageType(ProtocolMessageType.getContentType(contentType[0]));
    }

    public CipherState getState() {
        return state;
    }

    public void setState(CipherState state) {
        this.state = state;
    }

    public ConnectionEndType getLocalConnectionEndType() {
        return tlsContext.getContext().getConnection().getLocalConnectionEndType();
    }

    public ConnectionEndType getConnectionEndType() {
        return tlsContext.getChooser().getConnectionEndType();
    }

    public Integer getDefaultAdditionalPadding() {
        return tlsContext.getConfig().getDefaultAdditionalPadding();
    }

    public ConnectionEndType getTalkingConnectionEndType() {
        return tlsContext.getTalkingConnectionEndType();
    }

    public Random getRandom() {
        return tlsContext.getRandom();
    }

    class PlaintextParser extends Parser<Object> {

        public PlaintextParser(byte[] array) {
            super(new ByteArrayInputStream(array));
        }

        @Override
        public void parse(Object t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public byte[] parseByteArrayField(int length) {
            return super.parseByteArrayField(length);
        }
    }
}
