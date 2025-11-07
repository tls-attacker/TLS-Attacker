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
import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.crypto.cipher.CipherWrapper;
import de.rub.nds.tlsattacker.core.crypto.mac.MacWrapper;
import de.rub.nds.tlsattacker.core.crypto.mac.WrappedMac;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.RecordCryptoComputations;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class RecordBlockCipher extends RecordCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    /** indicates if explicit IV values should be used (as in TLS 1.1 and higher) */
    private boolean useExplicitIv;

    /** mac for verification of incoming messages */
    private WrappedMac readMac;

    /** mac object for macing outgoing messages */
    private WrappedMac writeMac;

    public RecordBlockCipher(TlsContext tlsContext, CipherState state) {
        super(tlsContext, state);
        try {
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
            readMac =
                    MacWrapper.getMac(
                            getState().getVersion(),
                            getState().getCipherSuite(),
                            getState().getKeySet().getReadMacSecret(getLocalConnectionEndType()));
            writeMac =
                    MacWrapper.getMac(
                            getState().getVersion(),
                            getState().getCipherSuite(),
                            getState().getKeySet().getWriteMacSecret(getLocalConnectionEndType()));
            if (getState().getVersion().usesExplicitIv()) {
                useExplicitIv = true;
            } else {
                useExplicitIv = false;
                encryptCipher.setIv(getState().getKeySet().getWriteIv(getLocalConnectionEndType()));
                decryptCipher.setIv(getState().getKeySet().getReadIv(getLocalConnectionEndType()));
            }
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(
                    "Unsupported Cipher suite:" + getState().getCipherSuite().name(), e);
        }
    }

    private byte[] calculateMac(byte[] data, ConnectionEndType connectionEndType) {
        LOGGER.debug("The MAC was calculated over the following data: {}", data);
        byte[] result;
        if (connectionEndType == getConnectionEndType()) {
            result = writeMac.calculateMac(data);
        } else {
            result = readMac.calculateMac(data);
        }
        LOGGER.debug("MAC: {}", result);
        return result;
    }

    /**
     * Takes correctly padded data and encrypts it
     *
     * <p>The RequestedEncryption operation
     *
     * @return The EncryptionResult
     */
    private byte[] encrypt(byte[] plaintext, byte[] iv) throws CryptoException {
        byte[] expandedPlaintext = this.expandToBlocksize(plaintext);
        byte[] ciphertext = encryptCipher.encrypt(iv, expandedPlaintext);
        if (!useExplicitIv) {
            encryptCipher.setIv(extractNextEncryptIv(ciphertext));
        }
        LOGGER.debug("EncryptIv: {}", encryptCipher.getIv());
        return ciphertext;
    }

    @Override
    public void encrypt(Record record) throws CryptoException {
        if (record.getComputations() == null) {
            LOGGER.warn("Record computations are not prepared.");
            record.prepareComputations();
        }
        LOGGER.debug("Encrypting Record:");
        RecordCryptoComputations computations = record.getComputations();

        record.getComputations()
                .setMacKey(getState().getKeySet().getWriteMacSecret(getConnectionEndType()));
        record.getComputations()
                .setCipherKey(getState().getKeySet().getWriteKey(getConnectionEndType()));

        byte[] iv = getEncryptionIV();
        record.getComputations().setCbcInitialisationVector(iv);
        iv = record.getComputations().getCbcInitialisationVector().getValue();

        byte[] cleanBytes;
        if (getState().getVersion().isDTLS()
                && getState().getConnectionId() != null
                && getState().getConnectionId().length > 0) {
            cleanBytes = encapsulateRecordBytes(record);
            record.setContentType(ProtocolMessageType.TLS12_CID.getValue());
        } else {
            cleanBytes = record.getCleanProtocolMessageBytes().getValue();
        }

        if (getState().isEncryptThenMac()) {

            computations.setPadding(
                    calculatePadding(calculatePaddingLength(record, cleanBytes.length)));
            LOGGER.debug("Padding: {}", computations.getPadding().getValue());
            computations.setPlainRecordBytes(
                    DataConverter.concatenate(cleanBytes, computations.getPadding().getValue()));
            LOGGER.debug("PlainRecordBytes: {}", computations.getPlainRecordBytes().getValue());
            byte[] ciphertext = encrypt(computations.getPlainRecordBytes().getValue(), iv);
            computations.setCiphertext(ciphertext);
            if (useExplicitIv) {
                computations.setAuthenticatedNonMetaData(
                        DataConverter.concatenate(
                                iv, record.getComputations().getCiphertext().getValue()));
            } else {
                computations.setAuthenticatedNonMetaData(
                        record.getComputations().getCiphertext().getValue());
            }
            computations.setAuthenticatedMetaData(
                    collectAdditionalAuthenticatedData(record, getState().getVersion()));
            computations.setMac(
                    calculateMac(
                            DataConverter.concatenate(
                                    computations.getAuthenticatedMetaData().getValue(),
                                    computations.getAuthenticatedNonMetaData().getValue()),
                            getLocalConnectionEndType()));
            if (useExplicitIv) {
                record.setProtocolMessageBytes(
                        DataConverter.concatenate(
                                iv,
                                computations.getCiphertext().getValue(),
                                computations.getMac().getValue()));
            } else {
                record.setProtocolMessageBytes(
                        DataConverter.concatenate(
                                computations.getCiphertext().getValue(),
                                computations.getMac().getValue()));
            }
        } else {
            computations.setAuthenticatedNonMetaData(cleanBytes);
            computations.setAuthenticatedMetaData(
                    collectAdditionalAuthenticatedData(record, getState().getVersion()));
            computations.setMac(
                    calculateMac(
                            DataConverter.concatenate(
                                    computations.getAuthenticatedMetaData().getValue(),
                                    computations.getAuthenticatedNonMetaData().getValue()),
                            getLocalConnectionEndType()));

            computations.setPadding(
                    calculatePadding(
                            calculatePaddingLength(
                                    record,
                                    cleanBytes.length + computations.getMac().getValue().length)));
            LOGGER.debug("Padding: {}", computations.getPadding().getValue());

            record.getComputations()
                    .setPlainRecordBytes(
                            DataConverter.concatenate(
                                    cleanBytes,
                                    computations.getMac().getValue(),
                                    computations.getPadding().getValue()));
            LOGGER.debug("PlainRecordBytes: {}", computations.getPlainRecordBytes().getValue());

            computations.setCiphertext(
                    encrypt(record.getComputations().getPlainRecordBytes().getValue(), iv));

            if (useExplicitIv) {
                record.setProtocolMessageBytes(
                        DataConverter.concatenate(iv, computations.getCiphertext().getValue()));
            } else {
                record.setProtocolMessageBytes(computations.getCiphertext());
            }
        }

        // TODO - our own macs and paddings are "always" valid - this does not
        // respect modifications made on the variables
        computations.setPaddingValid(true);
        computations.setMacValid(true);
    }

    private byte[] extractNextEncryptIv(byte[] ciphertext) {
        return Arrays.copyOfRange(
                ciphertext, ciphertext.length - encryptCipher.getBlocksize(), ciphertext.length);
    }

    /**
     * Makes sure that the plaintext we are passing to the encrypt function is a multiple of the
     * blocksize
     *
     * @param plaintext
     * @return
     */
    private byte[] expandToBlocksize(byte[] plaintext) {
        byte[] expandedPlaintext = plaintext;
        int blocksize = this.encryptCipher.getBlocksize();
        if (plaintext != null && blocksize > 0 && (plaintext.length % blocksize) != 0) {
            int numberOfBlocks = (plaintext.length / blocksize) + 1;
            expandedPlaintext = new byte[numberOfBlocks * blocksize];
            System.arraycopy(plaintext, 0, expandedPlaintext, 0, plaintext.length);
        }
        return expandedPlaintext;
    }

    public byte[] calculatePadding(int paddingLength) {
        paddingLength = Math.abs(paddingLength);
        byte[] padding = new byte[paddingLength];
        for (int i = 0; i < paddingLength; i++) {
            padding[i] = (byte) (paddingLength - 1);
        }
        return padding;
    }

    public int calculatePaddingLength(Record record, int dataLength) {

        int additionalPadding = getDefaultAdditionalPadding();
        if (additionalPadding > 256) {
            LOGGER.warn("Additional padding is too big. setting it to max possible value");
            additionalPadding = 256;
        } else if (additionalPadding < 0) {
            LOGGER.warn("Additional padding is negative, setting it to 0");
            additionalPadding = 0;
        }
        record.getComputations().setAdditionalPaddingLength(additionalPadding);
        additionalPadding = record.getComputations().getAdditionalPaddingLength().getValue();
        if (additionalPadding % encryptCipher.getBlocksize() != 0) {
            LOGGER.warn("Additional padding is not a multiple of the blocksize");
        }
        return (encryptCipher.getBlocksize() - (dataLength % encryptCipher.getBlocksize()))
                + additionalPadding;
    }

    public byte[] getEncryptionIV() {
        if (useExplicitIv) {
            LOGGER.debug("Using explict IV");
            byte[] iv = new byte[getState().getCipherAlg().getNonceBytesFromHandshake()];
            getRandom().nextBytes(iv);
            return iv;
        } else {
            LOGGER.debug("Using implicit IV");
            byte[] tempIv = encryptCipher.getIv();
            if (tempIv == null) {
                LOGGER.debug("First IV - using from KeyBlock");
                ConnectionEndType localConEndType = getLocalConnectionEndType();
                return getState().getKeySet().getWriteIv(localConEndType);
            } else {
                return tempIv;
            }
        }
    }

    @Override
    public void decrypt(Record record) throws CryptoException {
        if (record.getComputations() == null) {
            LOGGER.warn("Record computations are not prepared.");
            record.prepareComputations();
        }
        LOGGER.debug("Decrypting Record");
        RecordCryptoComputations computations = record.getComputations();

        computations.setMacKey(getState().getKeySet().getReadMacSecret(getConnectionEndType()));
        computations.setCipherKey(getState().getKeySet().getReadKey(getConnectionEndType()));

        byte[] plaintext = record.getProtocolMessageBytes().getValue();
        PlaintextParser parser = new PlaintextParser(plaintext);
        try {
            byte[] iv;
            if (useExplicitIv) {
                LOGGER.debug("Using explicit IV");
                iv =
                        parser.parseByteArrayField(
                                getState().getCipherAlg().getNonceBytesFromHandshake());
            } else {
                LOGGER.debug("Using implicit IV");
                iv = decryptCipher.getIv();
            }
            LOGGER.debug("Using IV: {}", iv);
            record.getComputations().setCbcInitialisationVector(iv);

            int macLength = readMac.getMacLength();
            byte[] ciphertext;
            byte[] hmac = null;
            if (getState().isEncryptThenMac()) {
                int toParseCiphertextLength = parser.getBytesLeft() - macLength;
                if (toParseCiphertextLength < 0) {
                    throw new CryptoException("Record too small");
                }
                ciphertext = parser.parseByteArrayField(toParseCiphertextLength);
                hmac = parser.parseByteArrayField(macLength);
            } else {
                ciphertext = parser.parseByteArrayField(parser.getBytesLeft());
            }

            computations.setCiphertext(ciphertext);
            byte[] plainData = decryptCipher.decrypt(iv, computations.getCiphertext().getValue());
            computations.setPlainRecordBytes(plainData);
            plainData = computations.getPlainRecordBytes().getValue();

            LOGGER.debug("Decrypted plaintext: {}", plainData);
            int paddingLength = (plainData[plainData.length - 1] & 0xff) + 1;
            if (plainData.length - paddingLength < 0) {
                LOGGER.warn("Error while decrypting record. Padding length is wrong.");
                record.setCleanProtocolMessageBytes(plainData);
                return;
            }
            byte[] padding =
                    Arrays.copyOfRange(
                            plainData, plainData.length - paddingLength, plainData.length);
            computations.setPadding(padding);
            computations.setPaddingValid(isPaddingValid(padding));
            int cleanProtocolBytesLength;
            if (getState().isEncryptThenMac()) {
                cleanProtocolBytesLength = plainData.length - paddingLength;
            } else {
                cleanProtocolBytesLength = plainData.length - macLength - paddingLength;
            }

            PlaintextParser plaintextParser = new PlaintextParser(plainData);
            byte[] cleanProtocolBytes =
                    plaintextParser.parseByteArrayField(cleanProtocolBytesLength);

            if (getState().getVersion().isDTLS()
                    && record.getContentMessageType() == ProtocolMessageType.TLS12_CID) {
                parseEncapsulatedRecordBytes(cleanProtocolBytes, record);
            } else {
                record.setCleanProtocolMessageBytes(cleanProtocolBytes);
            }

            if (!getState().isEncryptThenMac()) {
                hmac = plaintextParser.parseByteArrayField(macLength);
            }
            computations.setMac(hmac);

            if (getState().isEncryptThenMac()) {
                if (useExplicitIv) {
                    computations.setAuthenticatedNonMetaData(
                            DataConverter.concatenate(
                                    record.getComputations()
                                            .getCbcInitialisationVector()
                                            .getValue(),
                                    record.getComputations().getCiphertext().getValue()));
                } else {
                    computations.setAuthenticatedNonMetaData(
                            record.getComputations().getCiphertext().getValue());
                }
            } else {
                computations.setAuthenticatedNonMetaData(cleanProtocolBytes);
            }

            computations.setAuthenticatedMetaData(
                    collectAdditionalAuthenticatedData(record, getState().getVersion()));

            byte[] calculatedHMAC =
                    calculateMac(
                            DataConverter.concatenate(
                                    computations.getAuthenticatedMetaData().getValue(),
                                    computations.getAuthenticatedNonMetaData().getValue()),
                            getLocalConnectionEndType().getPeer());

            computations.setMacValid(
                    Arrays.equals(calculatedHMAC, computations.getMac().getValue()));

        } catch (ParserException e) {
            LOGGER.warn(
                    "Could not find all components (plaintext, mac, padding) in plaintext record.");
            LOGGER.warn(
                    "This is probably us having the wrong keys. Depending on the application this may be fine.");
            LOGGER.warn("Setting clean bytes to protocol message bytes.");
            record.setCleanProtocolMessageBytes(record.getProtocolMessageBytes());

            computations.setMacValid(false);
            computations.setPaddingValid(false);
        }
    }

    private boolean isPaddingValid(byte[] padding) {
        if (padding.length == 0) {
            LOGGER.debug("Zero Byte Padding is invalid");
            return false;
        }
        if (getState().getVersion().isSSL()) {
            return padding.length == padding[padding.length - 1] + 1;
        }
        for (int i = 0; i < padding.length; i++) {
            if (DataConverter.byteToUnsignedInt(padding[i]) != padding.length - 1) {
                LOGGER.debug("Padding is invalid");
                return false;
            }
        }
        LOGGER.debug("Padding is valid");
        return true;
    }
}
