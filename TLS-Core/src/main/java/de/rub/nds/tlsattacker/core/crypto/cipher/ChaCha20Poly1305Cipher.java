/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * TLS-AEAD-Cipher "Chacha20Poly1305", based on BouncyCastle's class
 * "BcChaCha20Poly1305".
 * See RFC7905 for further information.
 */

package de.rub.nds.tlsattacker.core.crypto.cipher;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public class ChaCha20Poly1305Cipher implements EncryptionCipher, DecryptionCipher {

    private static final CipherAlgorithm algorithm = CipherAlgorithm.ChaCha20Poly1305;
    private static final Logger LOGGER = LogManager.getLogger();

    // init nonce with 0 in order to prevent errors in calculateRFC7905Iv()
    private long nonce = 0;

    private final boolean isEncrypting;
    private static final byte[] ZEROES = new byte[15];
    private int additionalDataLength = 0;

    // instanciate ChaCha20Poly1305 algorithms
    private final ChaCha7539Engine cipher = new ChaCha7539Engine();
    private final Poly1305 mac = new Poly1305();

    public ChaCha20Poly1305Cipher(boolean isEncrypting, byte[] key) {
        this.isEncrypting = isEncrypting;
        this.cipher.init(isEncrypting, new ParametersWithIV(new KeyParameter(key, 0, key.length), ZEROES, 0, 12));
    }

    /**
     * From RFC7905: AEAD_CHACHA20_POLY1305 requires a 96-bit nonce, which is
     * formed as follows: 1. The 64-bit recor sequence number is serialized as
     * an 8-byte, big-endian value and padded on the left with four 0x00 bytes.
     * 2. The padded sequence number is XORed with the client_write_IV (when the
     * client is sending) or server_write_IV (when the server is sending).
     */
    private byte[] calculateRFC7905Iv(byte[] iv) {
        byte[] temp = new byte[12];
        TlsUtils.writeUint64(this.nonce, temp, 4);
        for (int i = 0; i < 12; ++i) {
            temp[i] ^= iv[i];
        }
        return temp;
    }

    @Override
    public byte[] decrypt(byte[] someBytes) throws CryptoException {
        throw new UnsupportedOperationException("ChaCha20Poly1305 can only be used as an AEAD Cipher!");
    }

    @Override
    public byte[] decrypt(byte[] iv, byte[] someBytes) {
        return new byte[1];
    }

    @Override
    public byte[] decrypt(byte[] iv, int tagLength, byte[] someBytes) {
        throw new UnsupportedOperationException("ChaCha20Poly1305 can only be used as an AEAD Cipher!");
    }

    @Override
    public byte[] decrypt(byte[] iv, int tagLength, byte[] additionAuthenticatedData, byte[] someBytes) {
        additionalDataLength = additionAuthenticatedData.length;
        int ciphertextLength = someBytes.length - 16;
        byte[] plaintext = new byte[getOutputSize(someBytes.length)];
        byte[] rfc7905_iv = calculateRFC7905Iv(iv);
        LOGGER.debug("Decrypting with the following rfc7905_iv: {}", ArrayConverter.bytesToHexString(rfc7905_iv));

        this.cipher.init(this.isEncrypting, new ParametersWithIV(null, rfc7905_iv));
        initMAC();
        updateMAC(additionAuthenticatedData, 0, additionalDataLength);

        updateMAC(someBytes, 0, ciphertextLength);

        byte[] aadLengthLe = ArrayConverter.longToBytes(longToLittleEndian(Long.valueOf(additionalDataLength)), 8);
        byte[] ciphertextLengthLe = ArrayConverter.longToBytes(longToLittleEndian(Long.valueOf(ciphertextLength)), 8);

        byte[] calculatedMAC = ArrayConverter.concatenate(aadLengthLe, ciphertextLengthLe, 8);
        this.mac.update(calculatedMAC, 0, 16);
        this.mac.doFinal(calculatedMAC, 0);

        byte[] receivedMAC = Arrays.copyOfRange(someBytes, ciphertextLength, someBytes.length);
        if (!Arrays.constantTimeAreEqual(calculatedMAC, receivedMAC)) {
            LOGGER.warn("MAC-Verification failed (bad_record_mac), continuing anyways!");
        }
        this.cipher.processBytes(someBytes, 0, ciphertextLength, plaintext, 0);

        return plaintext;
    }

    @Override
    public byte[] encrypt(byte[] someBytes) throws CryptoException {
        throw new UnsupportedOperationException("ChaCha20Poly1305 can only be used as an AEAD Cipher!");
    }

    @Override
    public byte[] encrypt(byte[] iv, byte[] someBytes) {
        throw new UnsupportedOperationException("ChaCha20Poly1305 can only be used as an AEAD Cipher!");
    }

    @Override
    public byte[] encrypt(byte[] iv, int tagLength, byte[] someBytes) {
        throw new UnsupportedOperationException("ChaCha20Poly1305 can only be used as an AEAD Cipher!");
    }

    @Override
    public byte[] encrypt(byte[] iv, int tagLength, byte[] additionAuthenticatedData, byte[] someBytes) {
        int additionalDataLength = additionAuthenticatedData.length;
        int plaintextLength = someBytes.length;
        byte[] ciphertext = new byte[getOutputSize(plaintextLength)];
        byte[] rfc7905_iv = calculateRFC7905Iv(iv);
        LOGGER.debug("Encypting with the following RFV7905 IV: {}", ArrayConverter.bytesToHexString(rfc7905_iv));

        this.cipher.init(this.isEncrypting, new ParametersWithIV(null, rfc7905_iv));
        initMAC();
        updateMAC(additionAuthenticatedData, 0, additionalDataLength);
        cipher.processBytes(someBytes, 0, plaintextLength, ciphertext, 0);

        updateMAC(ciphertext, 0, plaintextLength);

        byte[] aadLengthLe = ArrayConverter.longToBytes(longToLittleEndian(Long.valueOf(additionalDataLength)), 8);
        byte[] plaintextLengthLe = ArrayConverter.longToBytes(longToLittleEndian(Long.valueOf(plaintextLength)), 8);
        byte[] aad_plaintextLengthsLe = ArrayConverter.concatenate(aadLengthLe, plaintextLengthLe, 8);

        mac.update(aad_plaintextLengthsLe, 0, 16);
        mac.doFinal(ciphertext, 0 + plaintextLength);

        return ciphertext;
    }

    @Override
    public int getBlocksize() {
        throw new UnsupportedOperationException("ChaCha20Poly1305 can only be used as an AEAD Cipher!");
    }

    @Override
    public byte[] getIv() {
        throw new UnsupportedOperationException();
    }

    private int getOutputSize(int inputLength) {
        return this.isEncrypting ? inputLength + 16 : inputLength - 16;
    }

    private void initMAC() {
        byte[] firstBlock = new byte[64];
        this.cipher.processBytes(firstBlock, 0, 64, firstBlock, 0);
        this.mac.init(new KeyParameter(firstBlock, 0, 32));
        Arrays.fill(firstBlock, (byte) 0);
    }

    private long longToLittleEndian(long bigEndian) {
        ByteBuffer buf = ByteBuffer.allocate(8);
        buf.order(ByteOrder.BIG_ENDIAN);
        buf.putLong(bigEndian);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        return buf.getLong(0);
    }

    @Override
    public void setIv(byte[] iv) {
        throw new UnsupportedOperationException("The IV has to be passed with the encrypt() call!");
    }

    @Override
    public void setNonce(long nonce) {
        this.nonce = nonce;
    }

    private void updateMAC(byte[] buf, int off, int len) {
        this.mac.update(buf, off, len);

        int partial = len % 16;
        if (partial != 0) {
            this.mac.update(ZEROES, 0, 16 - partial);
        }
    }

}
