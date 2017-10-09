/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.EncryptionResult;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.EncryptionRequest;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public final class RecordBlockCipher extends RecordCipher {

    /**
     * indicates if explicit IV values should be used (as in TLS 1.1 and higher)
     */
    private boolean useExplicitIv;
    /**
     * mac for verification of incoming messages
     */
    private Mac readMac;
    /**
     * mac object for macing outgoing messages
     */
    private Mac writeMac;
    /**
     * encryption IV
     */
    private IvParameterSpec encryptIv;
    /**
     * decryption IV
     */
    private IvParameterSpec decryptIv;

    public RecordBlockCipher(TlsContext context, KeySet keySet) {
        super(context, keySet);
        ProtocolVersion version = context.getChooser().getSelectedProtocolVersion();
        if (version == ProtocolVersion.TLS11 || version == ProtocolVersion.TLS12 || version == ProtocolVersion.DTLS10
                || version == ProtocolVersion.DTLS12) {
            useExplicitIv = true;
        }
        if (context.getConnectionEnd().getConnectionEndType() == ConnectionEndType.CLIENT) {
            initCipherAndMac(keySet.getClientWriteIv(), keySet.getServerWriteIv(), keySet.getServerWriteMacSecret(),
                    keySet.getClientWriteMacSecret());
        } else {
            initCipherAndMac(keySet.getServerWriteIv(), keySet.getClientWriteIv(), keySet.getClientWriteMacSecret(),
                    keySet.getServerWriteMacSecret());
        }
    }

    @Override
    public byte[] calculateMac(byte[] data) {
        writeMac.update(data);
        LOGGER.debug("The MAC was calculated over the following data: {}", ArrayConverter.bytesToHexString(data));
        byte[] result = writeMac.doFinal();
        LOGGER.debug("MAC result: {}", ArrayConverter.bytesToHexString(result));
        return result;
    }

    /**
     * Takes correctly padded data and encrypts it
     *
     * @param request
     * @return
     * @throws CryptoException
     */
    @Override
    public EncryptionResult encrypt(EncryptionRequest request) throws CryptoException {
        try {
            byte[] ciphertext;
            if (useExplicitIv) {
                encryptIv = new IvParameterSpec(request.getInitialisationVector());
                encryptCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(getKeySet().getKey(context.getTalkingConnectionEndType()),bulkCipherAlg.getJavaName()),encryptIv);
                ciphertext = encryptCipher.doFinal(request.getPlainText());
                return new EncryptionResult(encryptIv.getIV(), ciphertext, useExplicitIv);

            } else {
                byte[] iv = encryptCipher.getIV();
                ciphertext = encryptCipher.update(request.getPlainText());
                return new EncryptionResult(ciphertext, iv, false);
            }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException ex) {
            throw new CryptoException(ex);
        }
    }

    /**
     * Takes a ciphertext and decrypts it
     *
     * @param data
     *            correctly padded data
     * @return
     * @throws CryptoException
     */
    @Override
    public byte[] decrypt(byte[] data) throws CryptoException {
        try {
            byte[] plaintext;
            if (useExplicitIv) {
                decryptIv = new IvParameterSpec(Arrays.copyOf(data, decryptCipher.getBlockSize()));
                if (context.getConnectionEnd().getConnectionEndType() == ConnectionEndType.CLIENT) {
                    decryptCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(getKeySet().getServerWriteKey(),
                            bulkCipherAlg.getJavaName()), decryptIv);
                } else {
                    decryptCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(getKeySet().getClientWriteKey(),
                            bulkCipherAlg.getJavaName()), decryptIv);
                }
                plaintext = decryptCipher.doFinal(Arrays.copyOfRange(data, decryptCipher.getBlockSize(), data.length));
            } else {
                plaintext = decryptCipher.update(data);
            }
            return plaintext;
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException
                | InvalidKeyException | UnsupportedOperationException ex) {
            throw new CryptoException(ex);
        }
    }

    private void initCipherAndMac(byte[] encryptIvBytes, byte[] decryptIvBytes, byte[] macReadBytes,
            byte[] macWriteBytes) throws UnsupportedOperationException {
        CipherAlgorithm cipherAlg = AlgorithmResolver.getCipher(context.getChooser().getSelectedCipherSuite());
        try {
            encryptCipher = Cipher.getInstance(cipherAlg.getJavaName());
            decryptCipher = Cipher.getInstance(cipherAlg.getJavaName());
            MacAlgorithm macAlg = AlgorithmResolver.getMacAlgorithm(context.getChooser().getSelectedCipherSuite());
            readMac = Mac.getInstance(macAlg.getJavaName());
            writeMac = Mac.getInstance(macAlg.getJavaName());

        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            throw new UnsupportedOperationException("Cipher not supported: "
                    + context.getChooser().getSelectedCipherSuite().name(), ex);
        }
        encryptIv = new IvParameterSpec(encryptIvBytes);
        decryptIv = new IvParameterSpec(decryptIvBytes);
        SecretKey encryptKey;
        SecretKey decryptKey;
        if (context.getConnectionEnd().getConnectionEndType() == ConnectionEndType.CLIENT) {
            encryptKey = new SecretKeySpec(getKeySet().getClientWriteKey(), bulkCipherAlg.getJavaName());
            decryptKey = new SecretKeySpec(getKeySet().getServerWriteKey(), bulkCipherAlg.getJavaName());
        } else {
            decryptKey = new SecretKeySpec(getKeySet().getClientWriteKey(), bulkCipherAlg.getJavaName());
            encryptKey = new SecretKeySpec(getKeySet().getServerWriteKey(), bulkCipherAlg.getJavaName());
        }
        try {
            encryptCipher.init(Cipher.ENCRYPT_MODE, encryptKey, encryptIv);
            decryptCipher.init(Cipher.DECRYPT_MODE, decryptKey, decryptIv);
            readMac.init(new SecretKeySpec(macReadBytes, readMac.getAlgorithm()));
            writeMac.init(new SecretKeySpec(macWriteBytes, writeMac.getAlgorithm()));
        } catch (InvalidAlgorithmParameterException | InvalidKeyException E) {
            throw new UnsupportedOperationException("Unsupported Ciphersuite:"
                    + context.getChooser().getSelectedCipherSuite().name(), E);
        }
    }

    @Override
    public int getMacLength() {
        return readMac.getMacLength();
    }

    @Override
    public byte[] calculatePadding(int paddingLength) {
        paddingLength = Math.abs(paddingLength); // TODO why?!
        byte[] padding = new byte[paddingLength];
        for (int i = 0; i < paddingLength; i++) {
            padding[i] = (byte) (paddingLength - 1);
        }
        return padding;
    }

    @Override
    public int calculatePaddingLength(int dataLength) {
        return encryptCipher.getBlockSize() - (dataLength % encryptCipher.getBlockSize());
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
}
