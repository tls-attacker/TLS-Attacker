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
import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.constants.Bits;
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.crypto.cipher.CipherWrapper;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.Record;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordAEADCipher extends RecordCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    /** AEAD tag length in bytes for regular ciphers */
    private static final int AEAD_TAG_LENGTH = 16;

    /** AEAD tag length in bytes for CCM_8 ciphers */
    private static final int AEAD_CCM_8_TAG_LENGTH = 8;

    /** Stores the computed tag length */
    private final int aeadTagLength;

    /** Stores the computed tag length */
    private final int aeadExplicitLength;

    public RecordAEADCipher(TlsContext tlsContext, CipherState state) {
        super(tlsContext, state);
        encryptCipher =
                CipherWrapper.getEncryptionCipher(
                        getState().getCipherSuite(),
                        getLocalConnectionEndType(),
                        getState().getKeySet());
        decryptCipher =
                CipherWrapper.getDecryptionCipher(
                        getState().getCipherSuite(),
                        getLocalConnectionEndType(),
                        getState().getKeySet());

        if (getState().getCipherSuite().isCCM_8()) {
            aeadTagLength = AEAD_CCM_8_TAG_LENGTH;
        } else {
            aeadTagLength = AEAD_TAG_LENGTH;
        }
        if (getState().getVersion().is13()) {
            aeadExplicitLength = 0;
        } else {
            aeadExplicitLength =
                    getState().getCipherSuite().getCipherAlgorithm().getNonceBytesFromRecord();
        }
    }

    public int getAeadSizeIncrease() {
        if (getState().getVersion().is13()) {
            return aeadTagLength;
        } else {
            return aeadExplicitLength + aeadTagLength;
        }
    }

    private byte[] prepareEncryptionGcmNonce(byte[] aeadSalt, byte[] explicitNonce, Record record) {
        byte[] gcmNonce = DataConverter.concatenate(aeadSalt, explicitNonce);

        // Nonce construction is different for chacha & tls1.3
        if (getState().getVersion().is13()) {
            gcmNonce = preprocessIv(record.getSequenceNumber().getValue().longValue(), gcmNonce);
        } else if (getState().getCipherAlg() == CipherAlgorithm.CHACHA20_POLY1305) {
            if (getState().getVersion().isDTLS()) {
                gcmNonce =
                        preprocessIvforDtls(
                                record.getEpoch().getValue(),
                                record.getSequenceNumber().getValue().longValue(),
                                gcmNonce);
            } else {
                gcmNonce =
                        preprocessIv(record.getSequenceNumber().getValue().longValue(), gcmNonce);
            }
        } else if (getState().getCipherAlg() == CipherAlgorithm.UNOFFICIAL_CHACHA20_POLY1305) {
            if (getState().getVersion().isDTLS()) {
                gcmNonce =
                        DataConverter.concatenate(
                                DataConverter.intToBytes(
                                        record.getEpoch().getValue(), RecordByteLength.DTLS_EPOCH),
                                DataConverter.longToUint48Bytes(
                                        record.getSequenceNumber().getValue().longValue()));
            } else {
                gcmNonce =
                        DataConverter.longToUint64Bytes(
                                record.getSequenceNumber().getValue().longValue());
            }
        }
        record.getComputations().setGcmNonce(gcmNonce);
        gcmNonce = record.getComputations().getGcmNonce().getValue();
        return gcmNonce;
    }

    private byte[] prepareEncryptionAeadSalt(Record record) {
        byte[] aeadSalt = getState().getKeySet().getWriteIv(getLocalConnectionEndType());
        record.getComputations().setAeadSalt(aeadSalt);
        aeadSalt = record.getComputations().getAeadSalt().getValue();
        return aeadSalt;
    }

    private byte[] prepareEncryptionExplicitNonce(Record record) {
        byte[] explicitNonce =
                createExplicitNonce(record.getSequenceNumber().getValue().longValue());
        record.getComputations().setExplicitNonce(explicitNonce);
        explicitNonce = record.getComputations().getExplicitNonce().getValue();
        return explicitNonce;
    }

    private byte[] createExplicitNonce(long sequenceNumber) {
        byte[] explicitNonce;
        if (aeadExplicitLength > 0) {
            explicitNonce = DataConverter.longToBytes(sequenceNumber, aeadExplicitLength);
        } else {
            explicitNonce = new byte[aeadExplicitLength];
        }
        return explicitNonce;
    }

    @Override
    public void encrypt(Record record) throws CryptoException {
        LOGGER.debug("Encrypting Record");
        record.getComputations()
                .setCipherKey(getState().getKeySet().getWriteKey(getConnectionEndType()));
        if (getState().getVersion().is13()) {
            int additionalPadding = getDefaultAdditionalPadding();
            if (additionalPadding > 65536) {
                LOGGER.warn("Additional padding is too big. setting it to max possible value");
                additionalPadding = 65536;
            } else if (additionalPadding < 0) {
                LOGGER.warn("Additional padding is negative, setting it to 0");
                additionalPadding = 0;
            }
            record.getComputations().setPadding(new byte[additionalPadding]);
            record.getComputations().setPlainRecordBytes(encapsulateRecordBytes(record));
            record.setContentType(ProtocolMessageType.APPLICATION_DATA.getValue());
            // For TLS1.3 we need the length beforehand to compute the
            // authenticatedMetaData
            record.setLength(
                    record.getComputations().getPlainRecordBytes().getValue().length
                            + aeadTagLength);
        } else if (getState().getVersion().isDTLS()
                && getState().getConnectionId() != null
                && getState().getConnectionId().length > 0) {
            record.getComputations().setPlainRecordBytes(encapsulateRecordBytes(record));
            record.setContentType(ProtocolMessageType.TLS12_CID.getValue());
        } else {
            record.getComputations()
                    .setPlainRecordBytes(record.getCleanProtocolMessageBytes().getValue());
        }

        byte[] explicitNonce = prepareEncryptionExplicitNonce(record);
        byte[] aeadSalt = prepareEncryptionAeadSalt(record);
        byte[] gcmNonce = prepareEncryptionGcmNonce(aeadSalt, explicitNonce, record);

        LOGGER.debug("Encrypting AEAD with the following IV: {}", gcmNonce);
        byte[] additionalAuthenticatedData =
                collectAdditionalAuthenticatedData(record, getState().getVersion());
        record.getComputations().setAuthenticatedMetaData(additionalAuthenticatedData);
        additionalAuthenticatedData =
                record.getComputations().getAuthenticatedMetaData().getValue();

        LOGGER.debug("Encrypting AEAD with the following AAD: {}", additionalAuthenticatedData);

        byte[] plainBytes = record.getComputations().getPlainRecordBytes().getValue();
        byte[] wholeCipherText =
                encryptCipher.encrypt(
                        gcmNonce,
                        aeadTagLength * Bits.IN_A_BYTE,
                        additionalAuthenticatedData,
                        plainBytes);
        if (aeadTagLength > wholeCipherText.length) {
            throw new CryptoException(
                    "Could not encrypt data. Supposed Tag is longer than the ciphertext");
        }
        byte[] onlyCiphertext =
                Arrays.copyOfRange(wholeCipherText, 0, wholeCipherText.length - aeadTagLength);

        record.getComputations().setAuthenticatedNonMetaData(onlyCiphertext);

        byte[] authenticationTag =
                Arrays.copyOfRange(
                        wholeCipherText,
                        wholeCipherText.length - aeadTagLength,
                        wholeCipherText.length);

        record.getComputations().setAuthenticationTag(authenticationTag);
        authenticationTag = record.getComputations().getAuthenticationTag().getValue();

        record.getComputations().setCiphertext(onlyCiphertext);
        onlyCiphertext = record.getComputations().getCiphertext().getValue();

        record.setProtocolMessageBytes(
                DataConverter.concatenate(explicitNonce, onlyCiphertext, authenticationTag));
        // TODO our own authentication tags are always valid
        record.getComputations().setAuthenticationTagValid(true);
    }

    @Override
    public void decrypt(Record record) throws CryptoException {
        LOGGER.debug("Decrypting Record");
        record.getComputations()
                .setCipherKey(getState().getKeySet().getReadKey(getConnectionEndType()));

        byte[] protocolBytes = record.getProtocolMessageBytes().getValue();
        PlaintextParser parser = new PlaintextParser(protocolBytes);
        try {
            byte[] explicitNonce = parser.parseByteArrayField(aeadExplicitLength);
            record.getComputations().setExplicitNonce(explicitNonce);
            explicitNonce = record.getComputations().getExplicitNonce().getValue();

            byte[] salt = getState().getKeySet().getReadIv(getLocalConnectionEndType());
            record.getComputations().setAeadSalt(salt);
            salt = record.getComputations().getAeadSalt().getValue();

            byte[] cipherTextOnly =
                    parser.parseByteArrayField(parser.getBytesLeft() - aeadTagLength);
            record.getComputations().setCiphertext(cipherTextOnly);
            record.getComputations()
                    .setAuthenticatedNonMetaData(
                            record.getComputations().getCiphertext().getValue());

            byte[] additionalAuthenticatedData =
                    collectAdditionalAuthenticatedData(record, getState().getVersion());
            record.getComputations().setAuthenticatedMetaData(additionalAuthenticatedData);
            additionalAuthenticatedData =
                    record.getComputations().getAuthenticatedMetaData().getValue();

            LOGGER.debug("Decrypting AEAD with the following AAD: {}", additionalAuthenticatedData);

            byte[] gcmNonce = DataConverter.concatenate(salt, explicitNonce);

            // Nonce construction is different for chacha & tls1.3
            if (getState().getVersion().is13()) {
                gcmNonce =
                        preprocessIv(record.getSequenceNumber().getValue().longValue(), gcmNonce);
            } else if (getState().getCipherAlg() == CipherAlgorithm.CHACHA20_POLY1305) {
                if (getState().getVersion().isDTLS()) {
                    gcmNonce =
                            preprocessIvforDtls(
                                    record.getEpoch().getValue(),
                                    record.getSequenceNumber().getValue().longValue(),
                                    gcmNonce);
                } else {
                    gcmNonce =
                            preprocessIv(
                                    record.getSequenceNumber().getValue().longValue(), gcmNonce);
                }
            } else if (getState().getCipherAlg() == CipherAlgorithm.UNOFFICIAL_CHACHA20_POLY1305) {
                if (getState().getVersion().isDTLS()) {
                    gcmNonce =
                            DataConverter.concatenate(
                                    DataConverter.intToBytes(
                                            record.getEpoch().getValue(),
                                            RecordByteLength.DTLS_EPOCH),
                                    DataConverter.longToUint48Bytes(
                                            record.getSequenceNumber().getValue().longValue()));
                } else {
                    gcmNonce =
                            DataConverter.longToUint64Bytes(
                                    record.getSequenceNumber().getValue().longValue());
                }
            }
            record.getComputations().setGcmNonce(gcmNonce);
            gcmNonce = record.getComputations().getGcmNonce().getValue();

            LOGGER.debug("Decrypting AEAD with the following IV: {}", gcmNonce);

            byte[] authenticationTag = parser.parseByteArrayField(parser.getBytesLeft());

            record.getComputations().setAuthenticationTag(authenticationTag);
            authenticationTag = record.getComputations().getAuthenticationTag().getValue();
            // TODO it would be better if we had a separate CM implementation to do
            // the decryption

            try {
                byte[] plainRecordBytes =
                        decryptCipher.decrypt(
                                gcmNonce,
                                aeadTagLength * Bits.IN_A_BYTE,
                                additionalAuthenticatedData,
                                DataConverter.concatenate(cipherTextOnly, authenticationTag));

                record.getComputations().setAuthenticationTagValid(true);
                record.getComputations().setPlainRecordBytes(plainRecordBytes);
                plainRecordBytes = record.getComputations().getPlainRecordBytes().getValue();
                if (getState().getVersion().is13()
                        || (getState().getVersion().isDTLS()
                                && record.getContentMessageType()
                                        == ProtocolMessageType.TLS12_CID)) {
                    parseEncapsulatedRecordBytes(plainRecordBytes, record);
                } else {
                    record.setCleanProtocolMessageBytes(plainRecordBytes);
                }
            } catch (CryptoException e) {
                LOGGER.warn("Tag invalid", e);
                record.getComputations().setAuthenticationTagValid(false);
                throw new CryptoException(e);
            }
        } catch (ParserException e) {
            LOGGER.warn("Could not find all components (iv, ciphertext, tag) in record.");
            LOGGER.warn(
                    "This is probably us having the wrong keys. Depending on the application this may be fine.");
            LOGGER.warn("Setting clean bytes to protocol message bytes.");
            record.setCleanProtocolMessageBytes(record.getProtocolMessageBytes());
            record.getComputations().setAuthenticationTagValid(false);
        }
    }

    public byte[] preprocessIv(long sequenceNumber, byte[] iv) {
        byte[] padding = new byte[] {0x00, 0x00, 0x00, 0x00};
        byte[] temp =
                DataConverter.concatenate(padding, DataConverter.longToUint64Bytes(sequenceNumber));
        for (int i = 0; i < iv.length; ++i) {
            temp[i] ^= iv[i];
        }
        return temp;
    }

    public byte[] preprocessIvforDtls(int epoch, long sequenceNumber, byte[] iv) {
        byte[] padding = new byte[] {0x00, 0x00, 0x00, 0x00};
        byte[] temp =
                DataConverter.concatenate(
                        padding,
                        DataConverter.intToBytes(epoch, RecordByteLength.DTLS_EPOCH),
                        DataConverter.longToUint48Bytes(sequenceNumber));
        for (int i = 0; i < iv.length; ++i) {
            temp[i] ^= iv[i];
        }
        return temp;
    }
}
