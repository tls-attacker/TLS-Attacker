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
import de.rub.nds.tlsattacker.core.crypto.cipher.CipherWrapper;
import de.rub.nds.tlsattacker.core.crypto.mac.MacWrapper;
import de.rub.nds.tlsattacker.core.crypto.mac.WrappedMac;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.RecordCryptoComputations;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
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
     * @param request
     *            The RequestedEncryption operation
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
            LOGGER.debug("Using explict IV");
            CipherAlgorithm cipherAlgorithm = AlgorithmResolver.getCipher(cipherSuite);
            byte[] iv = new byte[cipherAlgorithm.getNonceBytesFromHandshake()];
            context.getRandom().nextBytes(iv);
            return iv;
        } else {
            LOGGER.debug("Using implicit IV");
            byte[] tempIv = encryptCipher.getIv();
            if (tempIv == null) {
                LOGGER.debug("First IV - using from Keyblock");
                ConnectionEndType localConEndType = context.getConnection().getLocalConnectionEndType();
                return getKeySet().getWriteIv(localConEndType);
            } else {
                return tempIv;
            }
        }
    }

    @Override
    public void encrypt(Record record) {
        if (record.getComputations() == null) {
            LOGGER.warn("Record computations are not prepared.");
            record.prepareComputations();
        }
        LOGGER.debug("Encrypting Record:");
        RecordCryptoComputations computations = record.getComputations();

        record.getComputations().setMacKey(getKeySet().getWriteMacSecret(context.getChooser().getConnectionEndType()));
        record.getComputations().setCipherKey(getKeySet().getWriteKey(context.getChooser().getConnectionEndType()));

        byte[] iv = getEncryptionIV();
        record.getComputations().setCbcInitialisationVector(iv);
        iv = record.getComputations().getCbcInitialisationVector().getValue();

        byte[] cleanBytes = record.getCleanProtocolMessageBytes().getValue();
        if (context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)) {
            computations.setUnpaddedRecordBytes(cleanBytes);
            computations.setPadding(calculatePadding(calculatePaddingLength(computations.getUnpaddedRecordBytes()
                    .getValue().length)));
            computations.setPlainRecordBytes(ArrayConverter.concatenate(computations.getUnpaddedRecordBytes()
                    .getValue(), computations.getPadding().getValue()));
            try {
                computations.setCiphertext(encrypt(record.getComputations().getPlainRecordBytes().getValue(), iv));
            } catch (CryptoException ex) {
                LOGGER.warn("Could not encrypt data, using unencrypted data instead", ex);
                computations.setCiphertext(record.getComputations().getPlainRecordBytes().getValue());
            }
            computations.setMac(calculateMac(ArrayConverter.concatenate(
                    collectAdditionalAuthenticatedData(record, version), computations.getCiphertext().getValue()),
                    context.getConnection().getLocalConnectionEndType()));
        } else {
            computations.setMac(calculateMac(
                    ArrayConverter.concatenate(collectAdditionalAuthenticatedData(record, version), cleanBytes),
                    context.getConnection().getLocalConnectionEndType()));
            computations.setPadding(calculatePadding(calculatePaddingLength(computations.getUnpaddedRecordBytes()
                    .getValue().length)));

            record.getComputations().setPlainRecordBytes(
                    ArrayConverter.concatenate(computations.getUnpaddedRecordBytes().getValue(), computations
                            .getPadding().getValue()));
            try {
                computations.setCiphertext(encrypt(record.getComputations().getPlainRecordBytes().getValue(), iv));
            } catch (CryptoException ex) {
                LOGGER.warn("Could not encrypt data, using unencrypted data instead", ex);
                computations.setCiphertext(record.getComputations().getPlainRecordBytes().getValue());
            }

        }
        if (useExplicitIv) {
            if (useExplicitIv) {
                record.setProtocolMessageBytes(ArrayConverter.concatenate(iv, computations.getCiphertext().getValue()));
            } else {
                record.setProtocolMessageBytes(computations.getCiphertext());
            }
        }
    }

    @Override
    public void decrypt(Record record) throws CryptoException {
        if (record.getComputations() == null) {
            LOGGER.warn("Record computations are not preapred.");
            record.prepareComputations();
        }
        LOGGER.debug("Decrypting Record");
        RecordCryptoComputations computations = record.getComputations();

        computations.setMacKey(getKeySet().getReadMacSecret(context.getChooser().getConnectionEndType()));
        computations.setCipherKey(getKeySet().getReadKey(context.getChooser().getConnectionEndType()));

        byte[] plaintext = record.getProtocolMessageBytes().getValue();
        DecryptionParser parser = new DecryptionParser(0, plaintext);
        CipherSuite cipherSuite = context.getChooser().getSelectedCipherSuite();

        byte[] iv;
        if (useExplicitIv) {
            LOGGER.debug("Using explicit IV");
            CipherAlgorithm cipherAlgorithm = AlgorithmResolver.getCipher(cipherSuite);
            iv = parser.parseByteArrayField(cipherAlgorithm.getNonceBytesFromHandshake()); // TODO
                                                                                           // check
                                                                                           // length?
        } else {
            LOGGER.debug("Using implicit IV");
            iv = decryptCipher.getIv();
        }
        LOGGER.debug("Using IV:" + ArrayConverter.bytesToHexString(iv));
        record.getComputations().setCbcInitialisationVector(iv);

        if (context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)) {
            int macLength = readMac.getMacLength();
            int toParseCiphertextLenght = parser.getBytesLeft() - macLength;
            if (toParseCiphertextLenght < 0) {
                throw new CryptoException("Record too small");
            }
            byte[] ciphertext = parser.parseByteArrayField(toParseCiphertextLenght);
            computations.setCiphertext(ciphertext);

            byte[] hmac = parser.parseByteArrayField(macLength);
            computations.setMac(hmac);

            byte[] plainData = decryptCipher.decrypt(iv, ciphertext);
            computations.setPlainRecordBytes(plainData);
            plainData = computations.getPlainRecordBytes().getValue();

            parser = new DecryptionParser(0, plainData);
            byte[] cleanProtocolBytes = parser.parseByteArrayField(plainData.length - plainData[plainData.length - 1]
                    + 1);
            record.setCleanProtocolMessageBytes(cleanProtocolBytes);

            byte[] padding = parser.parseByteArrayField(plainData[plainData.length - 1] + 1);
            computations.setPadding(padding);

            computations.setPaddingValid(isPaddingValid(computations.getPadding().getValue()));
        } else {
            byte[] ciphertext = parser.parseByteArrayField(parser.getBytesLeft());
            byte[] plainData = decryptCipher.decrypt(iv, ciphertext);

            computations.setPlainRecordBytes(plainData);
            plainData = computations.getPlainRecordBytes().getValue();

            parser = new DecryptionParser(0, plainData);
            byte[] cleanProtocolBytes = parser.parseByteArrayField(plainData.length - readMac.getMacLength()
                    - plainData[plainData.length - 1] + 1);
            record.setCleanProtocolMessageBytes(cleanProtocolBytes);

            byte[] hmac = parser.parseByteArrayField(readMac.getMacLength());
            record.getComputations().setMac(hmac);

            byte[] padding = parser.parseByteArrayField(plainData[plainData.length - 1] + 1);
            computations.setPadding(padding);
        }
    }

    private boolean isPaddingValid(byte[] padding) {
        if (context.getChooser().getSelectedProtocolVersion().isSSL()) {
            return padding.length == padding[padding.length - 1] + 1;
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

    @Override
    public void encrypt(BlobRecord br) throws CryptoException {
        LOGGER.debug("Encrypting BlobRecord");
        br.setProtocolMessageBytes(encryptCipher.encrypt(br.getCleanProtocolMessageBytes().getValue()));
    }

    @Override
    public void decrypt(BlobRecord br) throws CryptoException {
        LOGGER.debug("Derypting BlobRecord");
        br.setProtocolMessageBytes(decryptCipher.decrypt(br.getCleanProtocolMessageBytes().getValue()));
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
