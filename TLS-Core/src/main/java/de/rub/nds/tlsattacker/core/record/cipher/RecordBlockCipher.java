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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.state.TlsContext;

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
        if (version.usesExplicitIv()) {
            useExplicitIv = true;
        }
        initCipherAndMac();

    }

    private void initCipherAndMac() throws UnsupportedOperationException {
        CipherAlgorithm cipherAlg = AlgorithmResolver.getCipher(cipherSuite);

        try {
            encryptCipher = Cipher.getInstance(cipherAlg.getJavaName());
            decryptCipher = Cipher.getInstance(cipherAlg.getJavaName());
            MacAlgorithm macAlg = AlgorithmResolver.getMacAlgorithm(context.getChooser().getSelectedProtocolVersion(),
                    cipherSuite);
            readMac = Mac.getInstance(macAlg.getJavaName());
            writeMac = Mac.getInstance(macAlg.getJavaName());

            readMac.init(new SecretKeySpec(getKeySet().getReadMacSecret(
                    context.getConnectionEnd().getConnectionEndType()), readMac.getAlgorithm()));
            writeMac.init(new SecretKeySpec(getKeySet().getWriteMacSecret(
                    context.getConnectionEnd().getConnectionEndType()), writeMac.getAlgorithm()));
            if (getKeySet().getClientWriteIv() != null && getKeySet().getServerWriteIv() != null) {
                encryptIv = new IvParameterSpec(getKeySet().getWriteIv(
                        context.getConnectionEnd().getConnectionEndType()));
                decryptIv = new IvParameterSpec(getKeySet()
                        .getReadIv(context.getConnectionEnd().getConnectionEndType()));
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException E) {
            throw new UnsupportedOperationException("Unsupported Ciphersuite:" + cipherSuite.name(), E);
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
     *            The RequestedEncryption operation
     * @return The EncryptionResult
     * @throws CryptoException
     *             If something goes wrong during Encryption
     */
    @Override
    public EncryptionResult encrypt(EncryptionRequest request) throws CryptoException {
        try {
            byte[] ciphertext;
            encryptIv = new IvParameterSpec(request.getInitialisationVector());
            encryptCipher.init(
                    Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(getKeySet().getWriteKey(context.getTalkingConnectionEndType()), bulkCipherAlg
                            .getJavaName()), encryptIv);
            ciphertext = encryptCipher.update(request.getPlainText());
            if (!useExplicitIv) {
                setNextIv(ciphertext);
            }
            return new EncryptionResult(encryptIv.getIV(), ciphertext, useExplicitIv);

        } catch (InvalidKeyException | InvalidAlgorithmParameterException ex) {
            throw new CryptoException(ex);
        }
    }

    private void setNextIv(byte[] ciphertext) {
        encryptIv = new IvParameterSpec(Arrays.copyOfRange(ciphertext,
                ciphertext.length - encryptCipher.getBlockSize(), ciphertext.length));
    }

    /**
     * Takes a ciphertext and decrypts it
     *
     * @param data
     *            correctly padded data
     * @return The raw decrypted Bytes
     * @throws CryptoException
     */
    @Override
    public byte[] decrypt(byte[] data) throws CryptoException {
        try {
            byte[] plaintext;
            if (useExplicitIv) {
                decryptIv = new IvParameterSpec(Arrays.copyOf(data, decryptCipher.getBlockSize()));
                decryptCipher.init(Cipher.DECRYPT_MODE,
                        new SecretKeySpec(getKeySet().getReadKey(context.getConnectionEnd().getConnectionEndType()),
                                bulkCipherAlg.getJavaName()), decryptIv);
                plaintext = decryptCipher.doFinal(Arrays.copyOfRange(data, decryptCipher.getBlockSize(), data.length));
            } else {
                decryptIv = new IvParameterSpec(getDecryptionIV());
                decryptCipher.init(Cipher.DECRYPT_MODE,
                        new SecretKeySpec(getKeySet().getReadKey(context.getConnectionEnd().getConnectionEndType()),
                                bulkCipherAlg.getJavaName()), decryptIv);
                plaintext = decryptCipher.doFinal(data);
            }
            return plaintext;
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException
                | InvalidKeyException | UnsupportedOperationException ex) {
            throw new CryptoException(ex);
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

    @Override
    public byte[] getEncryptionIV() {
        if (useExplicitIv) {
            CipherAlgorithm cipherAlgorithm = AlgorithmResolver.getCipher(cipherSuite);
            byte[] iv = new byte[cipherAlgorithm.getNonceBytesFromHandshake()];
            context.getRandom().nextBytes(iv);
            return iv;
        } else {
            return encryptIv.getIV();
        }
    }

    @Override
    public byte[] getDecryptionIV() {
        if (useExplicitIv) {
            return new byte[0];
        } else {
            return decryptIv.getIV();
        }
    }
}
