/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.tls.crypto.impl.bc.BcChaCha20Poly1305;

/**
 * TLS-AEAD-Cipher "Chacha20Poly1305", based on BouncyCastle's class
 * "BcChaCha20Poly1305". URL:
 * https://github.com/bcgit/bc-java/blob/master/tls/src
 * /main/java/org/bouncycastle/tls/crypto/impl/bc/BcChaCha20Poly1305.java See
 * RFC7905 for further information.
 */
public class ChaCha20Poly1305Cipher implements EncryptionCipher, DecryptionCipher {

    private final CipherAlgorithm algorithm = CipherAlgorithm.ChaCha20Poly1305;
    private static final Logger LOGGER = LogManager.getLogger();

    private long nonce = (-1);

    private final BcChaCha20Poly1305 bc_cipher;

    public ChaCha20Poly1305Cipher(boolean isEncrypting, byte[] key) {
        bc_cipher = new BcChaCha20Poly1305(isEncrypting);
        try {
            bc_cipher.setKey(key, 0, key.length);
        } catch (IOException e) {
            LOGGER.error("Something is wrong with the provided key!");
        }
    }

    @Override
    public byte[] encrypt(byte[] someBytes) throws CryptoException {
        throw new UnsupportedOperationException("ChaCha20Poly1305 can only be used as an AEAD Cipher!");
    }

    @Override
    public byte[] decrypt(byte[] someBytes) throws CryptoException {
        throw new UnsupportedOperationException("ChaCha20Poly1305 can only be used as an AEAD Cipher!");
    }

    @Override
    public byte[] encrypt(byte[] iv, byte[] someBytes) {
        throw new UnsupportedOperationException("ChaCha20Poly1305 can only be used as an AEAD Cipher!");
    }

    @Override
    public byte[] decrypt(byte[] iv, byte[] someBytes) {
        return new byte[1];
    }

    @Override
    public byte[] encrypt(byte[] iv, int tagLength, byte[] someBytes) {
        throw new UnsupportedOperationException("ChaCha20Poly1305 can only be used as an AEAD Cipher!");
    }

    @Override
    public byte[] decrypt(byte[] iv, int tagLength, byte[] someBytes) {
        throw new UnsupportedOperationException("ChaCha20Poly1305 can only be used as an AEAD Cipher!");
    }

    @Override
    public byte[] encrypt(byte[] iv, int tagLength, byte[] additionAuthenticatedData, byte[] someBytes) {
        LOGGER.info("Encyption: input iv: {}", ArrayConverter.bytesToHexString(iv));
        byte[] ciphertext = new byte[bc_cipher.getOutputSize(someBytes.length)];
        try {
            byte[] rfc7905_iv = calculateRFC7905Iv(iv);
            LOGGER.info("Encyption: rfc iv: {}", ArrayConverter.bytesToHexString(rfc7905_iv));
            LOGGER.info("Encyption: input AAD: {}", ArrayConverter.bytesToHexString(additionAuthenticatedData));
            LOGGER.info("Encyption: input plaintext: {}", ArrayConverter.bytesToHexString(someBytes));
            LOGGER.info("Encyption: max. output size: {}", String.valueOf(bc_cipher.getOutputSize(someBytes.length)));

            // init BC Cipher
            bc_cipher.init(rfc7905_iv, tagLength, additionAuthenticatedData);

            // Encrypt with BC Cipher int output_size =
            bc_cipher.doFinal(someBytes, 0, someBytes.length, ciphertext, 0);

            LOGGER.info("Encyption: Ciphertext|MAC-tag from BouncyCastle Cipher: {}",
                    ArrayConverter.bytesToHexString(ciphertext));
        } catch (IOException ex) {
            LOGGER.error(ex);
            return null;
        } catch (CryptoException ex) {
            LOGGER.error("Encyption: Something went wrong while calculating the RFC7905 IV!\n" + ex);
            return null;
        }
        return ciphertext;
    }

    @Override
    public byte[] decrypt(byte[] iv, int tagLength, byte[] additionAuthenticatedData, byte[] someBytes) {
        LOGGER.info("Decyption: input iv: {}", ArrayConverter.bytesToHexString(iv));
        byte[] plaintext = new byte[bc_cipher.getOutputSize(someBytes.length)];
        try {
            byte[] rfc7905_iv = calculateRFC7905Iv(iv);
            LOGGER.debug("Decrypting with the following rfc7905_iv: {}", ArrayConverter.bytesToHexString(rfc7905_iv));

            // init BC Cipher
            bc_cipher.init(rfc7905_iv, tagLength, additionAuthenticatedData);

            // Encrypt with BC Cipher int output_size =
            bc_cipher.doFinal(someBytes, 0, someBytes.length, plaintext, 0);
        } catch (IOException ex) {
            LOGGER.error(ex);
            return null;
        } catch (CryptoException ex) {
            LOGGER.error("Decyption: Something went wrong while calculating the RFC7905 IV!\n" + ex);
            return null;
        }
        return plaintext;
    }

    @Override
    public int getBlocksize() {
        throw new UnsupportedOperationException("ChaCha20Poly1305 can only be used as an AEAD Cipher!");
    }

    /**
     * Used to get the [client/server]_[read/write]_key-
     */
    @Override
    public byte[] getIv() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setIv(byte[] iv) {
        throw new UnsupportedOperationException("The IV has to be passed with the encrypt() call!");
    }

    @Override
    public void setNonce(long nonce) {
        this.nonce = nonce;
    }

    /**
     * From RFC7905: AEAD_CHACHA20_POLY1305 requires a 96-bit nonce, which is
     * formed as follows: 1. The 64-bit recor sequence number is serialized as
     * an 8-byte, big-endian value and padded on the left with four 0x00 bytes.
     * 2. The padded sequence number is XORed with the client_write_IV (when the
     * client is sending) or server_write_IV (when the server is sending).
     *
     * Method must be called after setNonce() and setIv() where called!
     */
    // TODO Robin remove unnecessary part when debugged!
    private byte[] calculateRFC7905Iv(byte[] iv) throws CryptoException {
        if (this.nonce == (-1)) {
            throw new CryptoException("Nonce has not been set!");
        }
        byte[] temp = new byte[12];
        TlsUtils.writeUint64(this.nonce, temp, 4);
        for (int i = 0; i < 12; ++i) {
            temp[i] ^= iv[i];
        }
        return temp;
    }

    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
