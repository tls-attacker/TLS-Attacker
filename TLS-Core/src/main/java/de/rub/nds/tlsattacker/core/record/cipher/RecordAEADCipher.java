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
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import static de.rub.nds.tlsattacker.core.record.cipher.RecordCipher.LOGGER;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.EncryptionRequest;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.EncryptionResult;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class RecordAEADCipher extends RecordCipher {

    /**
     * sequence Number length in byte
     */
    public static final int SEQUENCE_NUMBER_LENGTH = 8;
    /**
     * tag length in byte
     */
    public static final int GCM_TAG_LENGTH = 16;
    /**
     * iv length in byte
     */
    public static final int GCM_IV_LENGTH = 12;

    private GCMParameterSpec encryptIV;

    private GCMParameterSpec decryptIV;

    private final SecretKey encryptKey;

    private final SecretKey decryptKey;

    public RecordAEADCipher(TlsContext context, KeySet keySet) {
        super(context, keySet);
        encryptKey = new SecretKeySpec(keySet.getWriteKey(this.context.getConnection().getLocalConnectionEndType()),
                bulkCipherAlg.getJavaName());
        decryptKey = new SecretKeySpec(keySet.getReadKey(this.context.getConnection().getLocalConnectionEndType()),
                bulkCipherAlg.getJavaName());
        try {
            CipherAlgorithm cipherAlg = AlgorithmResolver.getCipher(cipherSuite);
            encryptCipher = Cipher.getInstance(cipherAlg.getJavaName());
            decryptCipher = Cipher.getInstance(cipherAlg.getJavaName());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            throw new UnsupportedOperationException("Could not initialize with:" + cipherSuite, ex);
        }

    }

    @Override
    public EncryptionResult encrypt(EncryptionRequest request) {
        if (version.isTLS13()) {
            return encryptTLS13(request);
        } else {
            return encryptTLS12(request);
        }
    }

    @Override
    public byte[] decrypt(byte[] data) {
        if (version.isTLS13()) {
            return decryptTLS13(data);
        } else {
            return decryptTLS12(data);
        }
    }

    private EncryptionResult encryptTLS13(EncryptionRequest request) {
        try {
            byte[] sequenceNumberByte = ArrayConverter.longToBytes(context.getWriteSequenceNumber(),
                    RecordByteLength.SEQUENCE_NUMBER);
            byte[] nonce = ArrayConverter.concatenate(new byte[GCM_IV_LENGTH - RecordByteLength.SEQUENCE_NUMBER],
                    sequenceNumberByte);
            encryptIV = prepareAeadParameters(nonce, getEncryptionIV());
            LOGGER.debug("Encrypting GCM with the following IV: {}", ArrayConverter.bytesToHexString(encryptIV.getIV()));
            encryptCipher.init(Cipher.ENCRYPT_MODE, encryptKey, encryptIV);
            return new EncryptionResult(encryptIV.getIV(), encryptCipher.doFinal(request.getPlainText()), false);
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException
                | InvalidAlgorithmParameterException ex) {
            throw new CryptoException(ex);
        }
    }

    private GCMParameterSpec prepareAeadParameters(byte[] nonce, byte[] writeIv) {
        byte[] param = new byte[GCM_IV_LENGTH];
        for (int i = 0; i < GCM_IV_LENGTH; i++) {
            param[i] = (byte) (writeIv[i] ^ nonce[i]);
        }
        return new GCMParameterSpec(GCM_TAG_LENGTH * 8, param);
    }

    private EncryptionResult encryptTLS12(EncryptionRequest request) {
        try {
            byte[] nonce = ArrayConverter.longToBytes(context.getWriteSequenceNumber(),
                    RecordByteLength.SEQUENCE_NUMBER);
            byte[] iv = ArrayConverter.concatenate(
                    getKeySet().getWriteIv(context.getConnection().getLocalConnectionEndType()), nonce);
            encryptIV = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            LOGGER.debug("Encrypting GCM with the following IV: {}", ArrayConverter.bytesToHexString(encryptIV.getIV()));
            encryptCipher.init(Cipher.ENCRYPT_MODE, encryptKey, encryptIV);
            LOGGER.debug("Encrypting GCM with the following AAD: {}",
                    ArrayConverter.bytesToHexString(additionalAuthenticatedData));
            encryptCipher.updateAAD(additionalAuthenticatedData);
            byte[] ciphertext = encryptCipher.doFinal(request.getPlainText());
            return new EncryptionResult(encryptIV.getIV(), ArrayConverter.concatenate(nonce, ciphertext), false);
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException
                | InvalidAlgorithmParameterException ex) {
            throw new CryptoException(ex);
        }
    }

    private byte[] decryptTLS13(byte[] data) {
        try {
            LOGGER.debug("Decrypting using SQN:" + context.getReadSequenceNumber());
            byte[] sequenceNumberByte = ArrayConverter.longToBytes(context.getReadSequenceNumber(),
                    RecordByteLength.SEQUENCE_NUMBER);
            byte[] nonce = ArrayConverter.concatenate(new byte[GCM_IV_LENGTH - RecordByteLength.SEQUENCE_NUMBER],
                    sequenceNumberByte);
            decryptIV = prepareAeadParameters(nonce, getDecryptionIV());
            LOGGER.debug("Decrypting GCM with the following IV: {}", ArrayConverter.bytesToHexString(decryptIV.getIV()));
            decryptCipher.init(Cipher.DECRYPT_MODE, decryptKey, decryptIV);
            LOGGER.debug("Decrypting the following GCM ciphertext: {}", ArrayConverter.bytesToHexString(data));
            return decryptCipher.doFinal(data);
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException
                | InvalidAlgorithmParameterException ex) {
            throw new CryptoException(ex);
        }
    }

    private byte[] decryptTLS12(byte[] data) {
        try {
            byte[] nonce = Arrays.copyOf(data, SEQUENCE_NUMBER_LENGTH);
            data = Arrays.copyOfRange(data, SEQUENCE_NUMBER_LENGTH, data.length);
            byte[] iv = ArrayConverter.concatenate(
                    getKeySet().getReadIv(context.getConnection().getLocalConnectionEndType()), nonce);
            decryptIV = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            LOGGER.debug("Decrypting GCM with the following IV: {}", ArrayConverter.bytesToHexString(decryptIV.getIV()));
            decryptCipher.init(Cipher.DECRYPT_MODE, decryptKey, decryptIV);
            LOGGER.debug("Decrypting GCM with the following AAD: {}",
                    ArrayConverter.bytesToHexString(additionalAuthenticatedData));
            decryptCipher.updateAAD(additionalAuthenticatedData);
            LOGGER.debug("Decrypting the following GCM ciphertext: {}", ArrayConverter.bytesToHexString(data));
            return decryptCipher.doFinal(data);
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException
                | InvalidAlgorithmParameterException ex) {
            throw new CryptoException(ex);
        }
    }

    @Override
    public boolean isUsingPadding() {
        if (version.isTLS13()) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public boolean isUsingMac() {
        return false;
    }

    @Override
    public boolean isUsingTags() {
        return true;
    }

    @Override
    public int getTagSize() {
        return SEQUENCE_NUMBER_LENGTH + GCM_TAG_LENGTH;
    }

    @Override
    public byte[] getEncryptionIV() {
        byte[] nonce = ArrayConverter.longToBytes(context.getWriteSequenceNumber(), SEQUENCE_NUMBER_LENGTH);
        return ArrayConverter.concatenate(getKeySet().getWriteIv(context.getConnection().getLocalConnectionEndType()),
                nonce);
    }

    @Override
    public byte[] getDecryptionIV() {
        byte[] nonce = ArrayConverter.longToBytes(context.getReadSequenceNumber(), SEQUENCE_NUMBER_LENGTH);
        return ArrayConverter.concatenate(getKeySet().getReadIv(context.getConnection().getLocalConnectionEndType()),
                nonce);
    }
}
