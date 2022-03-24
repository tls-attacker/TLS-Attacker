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
import de.rub.nds.tlsattacker.core.crypto.cipher.CipherWrapper;
import de.rub.nds.tlsattacker.core.crypto.mac.MacWrapper;
import de.rub.nds.tlsattacker.core.crypto.mac.WrappedMac;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.Parser;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.RecordCryptoComputations;
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

    public RecordBlockCipher(TlsContext context, CipherState state) {
        super(context, state);
        try {
            encryptCipher = CipherWrapper.getEncryptionCipher(getState().getCipherSuite(), getLocalConnectionEndType(),
                getState().getKeySet());
            decryptCipher = CipherWrapper.getDecryptionCipher(getState().getCipherSuite(), getLocalConnectionEndType(),
                getState().getKeySet());
            readMac = MacWrapper.getMac(getState().getVersion(), getState().getCipherSuite(),
                getState().getKeySet().getReadMacSecret(getLocalConnectionEndType()));
            writeMac = MacWrapper.getMac(getState().getVersion(), getState().getCipherSuite(),
                getState().getKeySet().getWriteMacSecret(getLocalConnectionEndType()));
            if (getState().getVersion().usesExplicitIv()) {
                useExplicitIv = true;
            } else {
                useExplicitIv = false;
                encryptCipher.setIv(getState().getKeySet().getWriteIv(getLocalConnectionEndType()));
                decryptCipher.setIv(getState().getKeySet().getReadIv(getLocalConnectionEndType()));
            }
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException("Unsupported Cipher suite:" + getState().getCipherSuite().name(),
                e);
        }
    }

    private byte[] calculateMac(byte[] data, ConnectionEndType connectionEndType) {
        LOGGER.debug("The MAC was calculated over the following data: {}", ArrayConverter.bytesToHexString(data));
        byte[] result;
        if (connectionEndType == getConnectionEndType()) {
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
     * @param  request
     *                 The RequestedEncryption operation
     * @return         The EncryptionResult
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

    @Override
    public void encrypt(BlobRecord br) throws CryptoException {
        LOGGER.debug("Encrypting BlobRecord");
        br.setProtocolMessageBytes(encryptCipher.encrypt(br.getCleanProtocolMessageBytes().getValue()));
    }

    @Override
    public void encrypt(Record record) throws CryptoException {
        if (record.getComputations() == null) {
            LOGGER.warn("Record computations are not prepared.");
            record.prepareComputations();
        }
        LOGGER.debug("Encrypting Record:");
        RecordCryptoComputations computations = record.getComputations();

        record.getComputations().setMacKey(getState().getKeySet().getWriteMacSecret(getConnectionEndType()));
        record.getComputations().setCipherKey(getState().getKeySet().getWriteKey(getConnectionEndType()));

        byte[] iv = getEncryptionIV();
        record.getComputations().setCbcInitialisationVector(iv);
        iv = record.getComputations().getCbcInitialisationVector().getValue();

        byte[] cleanBytes = record.getCleanProtocolMessageBytes().getValue();
        if (getState().isEncryptThenMac()) {

            computations.setPadding(calculatePadding(calculatePaddingLength(record, cleanBytes.length)));
            LOGGER.debug("Padding: " + ArrayConverter.bytesToHexString(computations.getPadding().getValue()));
            computations
                .setPlainRecordBytes(ArrayConverter.concatenate(cleanBytes, computations.getPadding().getValue()));
            LOGGER.debug(
                "PlainRecordBytes: " + ArrayConverter.bytesToHexString(computations.getPlainRecordBytes().getValue()));
            byte[] ciphertext = encrypt(computations.getPlainRecordBytes().getValue(), iv);
            computations.setCiphertext(ciphertext);
            if (useExplicitIv) {
                computations.setAuthenticatedNonMetaData(
                    ArrayConverter.concatenate(iv, record.getComputations().getCiphertext().getValue()));
            } else {
                computations.setAuthenticatedNonMetaData(record.getComputations().getCiphertext().getValue());
            }
            computations.setAuthenticatedMetaData(collectAdditionalAuthenticatedData(record, getState().getVersion()));
            computations
                .setMac(calculateMac(ArrayConverter.concatenate(computations.getAuthenticatedMetaData().getValue(),
                    computations.getAuthenticatedNonMetaData().getValue()), getLocalConnectionEndType()));
            if (useExplicitIv) {
                record.setProtocolMessageBytes(ArrayConverter.concatenate(iv, computations.getCiphertext().getValue(),
                    computations.getMac().getValue()));
            } else {
                record.setProtocolMessageBytes(ArrayConverter.concatenate(computations.getCiphertext().getValue(),
                    computations.getMac().getValue()));
            }
        } else {
            computations.setAuthenticatedNonMetaData(cleanBytes);
            computations.setAuthenticatedMetaData(collectAdditionalAuthenticatedData(record, getState().getVersion()));
            computations
                .setMac(calculateMac(ArrayConverter.concatenate(computations.getAuthenticatedMetaData().getValue(),
                    computations.getAuthenticatedNonMetaData().getValue()), getLocalConnectionEndType()));

            computations.setPadding(calculatePadding(
                calculatePaddingLength(record, cleanBytes.length + computations.getMac().getValue().length)));
            LOGGER.debug("Padding: " + ArrayConverter.bytesToHexString(computations.getPadding().getValue()));

            record.getComputations().setPlainRecordBytes(ArrayConverter.concatenate(cleanBytes,
                computations.getMac().getValue(), computations.getPadding().getValue()));
            LOGGER.debug(
                "PlainRecordBytes: " + ArrayConverter.bytesToHexString(computations.getPlainRecordBytes().getValue()));

            computations.setCiphertext(encrypt(record.getComputations().getPlainRecordBytes().getValue(), iv));

            if (useExplicitIv) {
                record.setProtocolMessageBytes(ArrayConverter.concatenate(iv, computations.getCiphertext().getValue()));
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
        return Arrays.copyOfRange(ciphertext, ciphertext.length - encryptCipher.getBlocksize(), ciphertext.length);
    }

    /**
     * Makes sure that the plaintext we are passing to the encrypt function is a multiple of the blocksize
     *
     * @param  plaintext
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
        return (encryptCipher.getBlocksize() - (dataLength % encryptCipher.getBlocksize())) + additionalPadding;
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
        DecryptionParser parser = new DecryptionParser(0, plaintext);

        byte[] iv;
        if (useExplicitIv) {
            LOGGER.debug("Using explicit IV");
            iv = parser.parseByteArrayField(getState().getCipherAlg().getNonceBytesFromHandshake());
        } else {
            LOGGER.debug("Using implicit IV");
            iv = decryptCipher.getIv();
        }
        LOGGER.debug("Using IV:" + ArrayConverter.bytesToHexString(iv));
        record.getComputations().setCbcInitialisationVector(iv);

        if (getState().isEncryptThenMac()) {
            int macLength = readMac.getMacLength();
            int toParseCiphertextLength = parser.getBytesLeft() - macLength;
            if (toParseCiphertextLength < 0) {
                throw new CryptoException("Record too small");
            }
            byte[] ciphertext = parser.parseByteArrayField(toParseCiphertextLength);
            computations.setCiphertext(ciphertext);

            byte[] hmac = parser.parseByteArrayField(macLength);
            computations.setMac(hmac);

            byte[] plainData = decryptCipher.decrypt(iv, ciphertext);
            computations.setPlainRecordBytes(plainData);
            plainData = computations.getPlainRecordBytes().getValue();

            LOGGER.debug("Decrypted plaintext: " + ArrayConverter.bytesToHexString(plainData));
            parser = new DecryptionParser(0, plainData);
            byte[] cleanProtocolBytes =
                parser.parseByteArrayField(plainData.length - (plainData[plainData.length - 1] + 1));
            record.setCleanProtocolMessageBytes(cleanProtocolBytes);
            if (useExplicitIv) {
                computations.setAuthenticatedNonMetaData(
                    ArrayConverter.concatenate(record.getComputations().getCbcInitialisationVector().getValue(),
                        record.getComputations().getCiphertext().getValue()));
            } else {
                computations.setAuthenticatedNonMetaData(record.getComputations().getCiphertext().getValue());
            }
            computations.setAuthenticatedMetaData(collectAdditionalAuthenticatedData(record, getState().getVersion()));

            byte[] padding = parser.parseByteArrayField(plainData[plainData.length - 1] + 1);
            computations.setPadding(padding);
            computations.setPaddingValid(isPaddingValid(padding));

            byte[] calculatedHMAC =
                calculateMac(ArrayConverter.concatenate(computations.getAuthenticatedMetaData().getValue(),
                    computations.getAuthenticatedNonMetaData().getValue()), getLocalConnectionEndType().getPeer());
            computations.setMacValid(Arrays.equals(calculatedHMAC, computations.getMac().getValue()));
        } else {
            byte[] ciphertext = parser.parseByteArrayField(parser.getBytesLeft());
            computations.setCiphertext(ciphertext);
            ciphertext = computations.getCiphertext().getValue();

            byte[] plainData = decryptCipher.decrypt(iv, ciphertext);

            computations.setPlainRecordBytes(plainData);
            plainData = computations.getPlainRecordBytes().getValue();

            parser = new DecryptionParser(0, plainData);

            int paddingLength = ArrayConverter.bytesToInt(new byte[] { plainData[plainData.length - 1] }) + 1;
            int cleanBytesLength = plainData.length - readMac.getMacLength() - paddingLength;

            byte[] cleanProtocolBytes;
            byte[] padding;
            byte[] hmac;
            if (cleanBytesLength < 0) {
                LOGGER.warn("Plain Data cannot fit Mac and Padding (due to length; invalid lengths detected)");
                padding = new byte[0];
                hmac = new byte[0];
                cleanProtocolBytes = parser.parseByteArrayField(plainData.length);
            } else {
                cleanProtocolBytes = parser.parseByteArrayField(cleanBytesLength);
                hmac = parser.parseByteArrayField(readMac.getMacLength());
                padding = parser.parseByteArrayField(paddingLength);
            }

            record.setCleanProtocolMessageBytes(cleanProtocolBytes);
            computations.setMac(hmac);
            computations.setPadding(padding);

            computations.setAuthenticatedNonMetaData(cleanProtocolBytes);
            computations.setAuthenticatedMetaData(collectAdditionalAuthenticatedData(record, getState().getVersion()));

            computations.setPaddingValid(isPaddingValid(padding));
            byte[] calculatedHMAC =
                calculateMac(ArrayConverter.concatenate(computations.getAuthenticatedMetaData().getValue(),
                    computations.getAuthenticatedNonMetaData().getValue()), getLocalConnectionEndType().getPeer());
            computations.setMacValid(Arrays.equals(calculatedHMAC, computations.getMac().getValue()));
        }

    }

    @Override
    public void decrypt(BlobRecord br) throws CryptoException {
        LOGGER.debug("Decrypting BlobRecord");
        br.setCleanProtocolMessageBytes(decryptCipher.decrypt(br.getProtocolMessageBytes().getValue()));
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
