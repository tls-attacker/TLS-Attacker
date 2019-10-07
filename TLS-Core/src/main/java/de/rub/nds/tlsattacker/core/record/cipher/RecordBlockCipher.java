/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.crypto.cipher.CipherWrapper;
import de.rub.nds.tlsattacker.core.crypto.mac.MacWrapper;
import de.rub.nds.tlsattacker.core.crypto.mac.WrappedMac;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.RecordCryptoComputations;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.DecryptionRequest;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.DecryptionResult;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.logging.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class RecordBlockCipher extends RecordCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * indicates if explicit IV values should be used (as in TLS 1.1 and higher)
     */
    private boolean useExplicitIv;
    /**
     * mac for verification of incoming messages
     */
    private WrappedMac readMac;
    /**
     * mac object for macing outgoing messages
     */
    private WrappedMac writeMac;

    public RecordBlockCipher(TlsContext context, KeySet keySet) {
        super(context, keySet);
        if (version.usesExplicitIv()) {
            useExplicitIv = true;
        }
        ConnectionEndType localConEndType = context.getConnection().getLocalConnectionEndType();

        try {
            encryptCipher = CipherWrapper.getEncryptionCipher(cipherSuite, localConEndType, getKeySet());
            decryptCipher = CipherWrapper.getDecryptionCipher(cipherSuite, localConEndType, getKeySet());
            readMac = MacWrapper.getMac(version, cipherSuite, getKeySet().getReadMacSecret(localConEndType));
            writeMac = MacWrapper.getMac(version, cipherSuite, getKeySet().getWriteMacSecret(localConEndType));
        } catch (NoSuchAlgorithmException E) {
            throw new UnsupportedOperationException("Unsupported Ciphersuite:" + cipherSuite.name(), E);
        }
    }

    private byte[] calculateMac(byte[] data, ConnectionEndType connectionEndType) {
        LOGGER.debug("The MAC was calculated over the following data: {}", ArrayConverter.bytesToHexString(data));
        byte[] result;
        if (connectionEndType == context.getChooser().getConnectionEndType()) {
            result = writeMac.calculateMac(data);
        } else {
            result = readMac.calculateMac(data);
        }
        LOGGER.debug("MAC: {}", ArrayConverter.bytesToHexString(result));
        return result;
    }

    /**
     * Takes correctly padded data and encrypts it
     *
     * @param request The RequestedEncryption operation
     * @return The EncryptionResult
     */
    private byte[] encrypt(byte[] plaintext, byte[] iv) throws CryptoException {
        byte[] expandedPlaintext = this.expandToBlocksize(plaintext);
        byte[] ciphertext = encryptCipher.encrypt(iv, expandedPlaintext);
        if (!useExplicitIv) {
            encryptCipher.setIv(extractNextEncryptIv(ciphertext));
        }
        LOGGER.debug("EncryptIv: " + ArrayConverter.bytesToHexString(encryptCipher.getIv()));
        return ciphertext;
    }

    private byte[] extractNextEncryptIv(byte[] ciphertext) {
        return Arrays.copyOfRange(ciphertext, ciphertext.length - encryptCipher.getBlocksize(), ciphertext.length);
    }

    /**
     * Makes sure that the plaintext we are passing to the encrypt function is a
     * multiple of the blocksize
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

    /**
     *
     * @param ciphertext
     * @param iv
     * @return
     */
    private byte[] decrypt(byte[] ciphertext, byte[] iv) throws CryptoException {

        byte[] plaintext;
        byte[] usedIv;
        if (ciphertext.length % decryptCipher.getBlocksize() != 0) {
            LOGGER.warn("Ciphertext is not a multiple of the Blocksize. Not Decrypting");
            return ciphertext;
        }
        if (useExplicitIv) {
            byte[] decryptIv = Arrays.copyOf(ciphertext, decryptCipher.getBlocksize());
            LOGGER.debug("decryptionIV: " + ArrayConverter.bytesToHexString(decryptIv));
            plaintext = decryptCipher.decrypt(decryptIv, Arrays.copyOfRange(ciphertext,
                    decryptCipher.getBlocksize(), ciphertext.length));
            usedIv = decryptIv;
        } else {
            byte[] decryptIv = iv;
            LOGGER.debug("decryptionIV: " + ArrayConverter.bytesToHexString(decryptIv));
            plaintext = decryptCipher.decrypt(decryptIv, ciphertext);

            decryptCipher.setIv(decryptIv);
        }
        return plaintext;
    }

    public byte[] calculatePadding(int paddingLength) {
        paddingLength = Math.abs(paddingLength);
        byte[] padding = new byte[paddingLength];
        for (int i = 0; i < paddingLength; i++) {
            padding[i] = (byte) (paddingLength - 1);
        }
        return padding;
    }

    public int calculatePaddingLength(int dataLength) {
        return encryptCipher.getBlocksize() - (dataLength % encryptCipher.getBlocksize());
    }

    @Override
    public boolean isUsingPadding() {
        return true;
    }

    @Override
    public boolean isUsingMac() {
        return true;
    }

    @Override
    public boolean isUsingTags() {
        return false;
    }

    public byte[] getEncryptionIV() {
        if (useExplicitIv) {
            CipherAlgorithm cipherAlgorithm = AlgorithmResolver.getCipher(cipherSuite);
            byte[] iv = new byte[cipherAlgorithm.getNonceBytesFromHandshake()];
            context.getRandom().nextBytes(iv);
            return iv;
        } else {
            byte[] tempIv = encryptCipher.getIv();
            if (tempIv == null) {
                ConnectionEndType localConEndType = context.getConnection().getLocalConnectionEndType();
                return getKeySet().getWriteIv(localConEndType);
            } else {
                return tempIv;
            }
        }
    }

    public byte[] getDecryptionIV() {
        if (useExplicitIv) {
            return new byte[0];
        } else {
            byte[] tempIv = decryptCipher.getIv();
            if (tempIv == null) {
                ConnectionEndType localConEndType = context.getConnection().getLocalConnectionEndType();
                return getKeySet().getReadIv(localConEndType);
            } else {
                return tempIv;
            }
        }
    }

    /**
     *
     * @param record
     */
    @Override
    public void encrypt(Record record) {
        if (record.getComputations() == null) {
            LOGGER.warn("Record computations are not preapred.");
            record.prepareComputations();
        }
        LOGGER.debug("Encrypting Record:");
        CipherSuite cipherSuite = context.getChooser().getSelectedCipherSuite();
        RecordCryptoComputations computations = record.getComputations();

        record.getComputations().setMacKey(getKeySet().getWriteMacSecret(context.getChooser().getConnectionEndType()));
        record.getComputations().setCipherKey(getKeySet().getWriteKey(context.getChooser().getConnectionEndType()));
        //TODO UPDATE CIPHER

        byte[] iv = getEncryptionIV();

        byte[] cleanBytes = record.getCleanProtocolMessageBytes().getValue();
        if (context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)) {
            computations.setUnpaddedRecordBytes(cleanBytes);
            computations.setPadding(calculatePadding(calculatePaddingLength(computations.getUnpaddedRecordBytes().getValue().length)));
            computations.setPlainRecordBytes(ArrayConverter.concatenate(computations.getUnpaddedRecordBytes().getValue(), computations.getPadding().getValue()));
            try {
                computations.setCiphertext(encrypt(record.getComputations().getPlainRecordBytes().getValue(), iv));
            } catch (CryptoException ex) {
                LOGGER.warn("Could not encrypt data, using unencrypted data instead", ex);
                computations.setCiphertext(record.getComputations().getPlainRecordBytes().getValue());
            }
            computations.setMac(calculateMac(ArrayConverter.concatenate(collectAdditionalAuthenticatedData(record, version), computations.getCiphertext().getValue()), context.getConnection().getLocalConnectionEndType()));
            if (useExplicitIv) {
                record.setProtocolMessageBytes(ArrayConverter.concatenate(iv, computations.getCiphertext().getValue(), computations.getMac().getValue()));
            } else {
                record.setProtocolMessageBytes(ArrayConverter.concatenate(computations.getCiphertext().getValue(), computations.getMac().getValue()));
            }
        } else {
            computations.setMac(calculateMac(ArrayConverter.concatenate(collectAdditionalAuthenticatedData(record, version), cleanBytes), context.getConnection().getLocalConnectionEndType()));
            computations.setPadding(calculatePadding(calculatePaddingLength(computations.getUnpaddedRecordBytes().getValue().length)));

            record.getComputations().setPlainRecordBytes(ArrayConverter.concatenate(computations.getUnpaddedRecordBytes().getValue(), computations.getPadding().getValue()));
            try {
                computations.setCiphertext(encrypt(record.getComputations().getPlainRecordBytes().getValue(), iv));
            } catch (CryptoException ex) {
                LOGGER.warn("Could not encrypt data, using unencrypted data instead", ex);
                computations.setCiphertext(record.getComputations().getPlainRecordBytes().getValue());
            }
            if (useExplicitIv) {
                if (useExplicitIv) {
                    record.setProtocolMessageBytes(ArrayConverter.concatenate(iv, computations.getCiphertext().getValue()));
                } else {
                    record.setProtocolMessageBytes(computations.getCiphertext());
                }
            }
        }
    }

    @Override
    public void decrypt(Record record) {
        if (record.getComputations() == null) {
            LOGGER.warn("Record computations are not preapred.");
            record.prepareComputations();
        }
        LOGGER.debug("Decrypting Record");
        RecordCryptoComputations computations = record.getComputations();

        computations.setMacKey(getKeySet().getReadMacSecret(context.getChooser().getConnectionEndType()));
        computations.setCipherKey(getKeySet().getReadKey(context.getChooser().getConnectionEndType()));
        //TODO UPDATE CIPHER

        byte[] protocolBytes = record.getProtocolMessageBytes().getValue();
        DecryptionParser parser = new DecryptionParser(0, protocolBytes);
        CipherSuite cipherSuite = context.getChooser().getSelectedCipherSuite();
        byte[] iv = null;
        if (useExplicitIv) {
            //extract IV
            CipherAlgorithm cipherAlgorithm = AlgorithmResolver.getCipher(cipherSuite);
            parser.parseByteArrayField(cipherAlgorithm.getNonceBytesFromHandshake()); //TODO check length?
        } else {
            //use last iv
            iv = decryptCipher.getIv();
        }
        if (context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)) {
            MacAlgorithm macAlgorithm = AlgorithmResolver.getMacAlgorithm(version, this.cipherSuite);
            int macLength = macAlgorithm.getSize();
            int toParseCiphertextLenght = parser.getBytesLeft() - macLength;
            //TODO if inParseCiphertextLength is >= 0
            byte[] ciphertext = parser.parseByteArrayField(toParseCiphertextLenght);
            byte[] hmac = parser.parseByteArrayField(macLength);
            computations.setCiphertext(ciphertext);
            computations.setMac(hmac);

            byte[] plainData = null;
            try {
                plainData = decrypt(ciphertext, iv);
            } catch (CryptoException ex) {
                //TODO
                java.util.logging.Logger.getLogger(RecordBlockCipher.class.getName()).log(Level.SEVERE, null, ex);
            }

            computations.setPlainRecordBytes(plainData);
            //Depad
            byte[] padding = depad(plainData);
            computations.setPadding(padding);
            byte[] plaintext = Arrays.copyOfRange(plainData, 0, plainData.length - padding.length);
            record.setCleanProtocolMessageBytes(plaintext);
        } else {

        }

        computations.setPlainRecordBytes(decrypt(protocolBytes, iv));
        prepareNonMetaDataMaced(record, protocolBytes);
        prepareAdditionalMetadata(record);
        if (isEncryptThenMac(cipherSuite)) {
            LOGGER.trace("EncryptThenMac is active");
            byte[] mac = parseMac(record.getProtocolMessageBytes().getValue());
            record.getComputations().setMac(mac);
            protocolBytes = removeMac(record.getProtocolMessageBytes().getValue());
        }
        LOGGER.debug("Decrypting:" + ArrayConverter.bytesToHexString(protocolBytes));
        DecryptionResult result = recordCipher.decrypt(new DecryptionRequest(record.getComputations()
                .getAuthenticatedMetaData().getValue(), protocolBytes));
        byte[] decrypted = result.getDecryptedCipherText();
        record.getComputations().setPlainRecordBytes(decrypted);
        record.getComputations().setInitialisationVector(result.getInitialisationVector());
        LOGGER.debug("PlainRecordBytes: "
                + ArrayConverter.bytesToHexString(record.getComputations().getPlainRecordBytes().getValue()));
        if (recordCipher.isUsingPadding() && result.isSuccessful()) {
            if (!context.getChooser().getSelectedProtocolVersion().isTLS13()
                    && context.getActiveKeySetTypeRead() != Tls13KeySetType.EARLY_TRAFFIC_SECRETS) {
                adjustPaddingTLS(record);
            } else {
                adjustPaddingTLS13(record);
            }
        } else {
            useNoPadding(record);
        }
        if (!isEncryptThenMac(cipherSuite) && recordCipher.isUsingMac() && result.isSuccessful()) {
            LOGGER.trace("EncryptThenMac is not active");
            if (cipherSuite.isUsingMac()) {
                adjustMac(record);
            } else {
                useNoMac(record);
            }
            prepareNonMetaDataMaced(record, record.getCleanProtocolMessageBytes().getValue());
            prepareAdditionalMetadata(record);

        } else {
            useNoMac(record);
        }
        context.increaseReadSequenceNumber();
        if (context.getChooser().getConnectionEndType() == ConnectionEndType.SERVER
                && context.getActiveClientKeySetType() == Tls13KeySetType.EARLY_TRAFFIC_SECRETS) {
            checkForEndOfEarlyData(record.getComputations().getUnpaddedRecordBytes().getValue());
        }
        if (result.isSuccessful()) {
            record.getComputations().setPaddingValid(isPaddingValid(record));
            record.getComputations().setMacValid(isMacValid(record));
        }
    }

    /**
     * Simple depadding function which returns the padding of the plain data.
     *
     * @param plainData the data that is supposed to contain padding
     * @return the padding of the plain data
     */
    private byte[] depad(byte[] plainData) throws CryptoException {
        int paddingStart = plainData.length - 1;
        if (paddingStart > plainData.length) {
            throw new CryptoException("Could parse Padding. Padding start greater than data length");
        }
        if (paddingStart < 0) {
            throw new CryptoException("Could not parse Padding. Padding start is negative");
        }
        return Arrays.copyOfRange(plainData, paddingStart, plainData.length);

    }

    private boolean isPaddingValid(byte[] padding) {
        if (context.getChooser().getSelectedProtocolVersion().isSSL()) {
            return padding.length >= p
        }
        for (int i = 0; i < padding.length; i++) {
            if (padding[i] != padding.length - 1) {
                LOGGER.debug("Padding is invalid");
                return false;
            }
        }
        LOGGER.debug("Padding is valid");
        return true;
    }

    class DecryptionParser extends Parser<Object> {

        public DecryptionParser(int startposition, byte[] array) {
            super(startposition, array);
        }

        @Override
        public Object parse() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public byte[] parseByteArrayField(int length) {
            return super.parseByteArrayField(length);
        }

        @Override
        public int getBytesLeft() {
            return super.getBytesLeft();
        }

        @Override
        public int getPointer() {
            return super.getPointer();
        }

    }
}
