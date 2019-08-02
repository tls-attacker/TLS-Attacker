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

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.cipher.RecordAEADCipher;
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

    private byte[] key;
    private static final byte[] ZEROES = new byte[RecordAEADCipher.AEAD_TAG_LENGTH - 1];
    private int additionalDataLength = 0;

    // instanciate ChaCha20Poly1305 algorithms
    private final ChaCha7539Engine cipher = new ChaCha7539Engine();
    private final Poly1305 mac = new Poly1305();

    public ChaCha20Poly1305Cipher(byte[] key) {
        this.key = key;
    }

    /**
     * From RFC7905: AEAD_CHACHA20_POLY1305 requires a 96-bit nonce, which is
     * formed as follows: 1. The 64-bit record sequence number is serialized as
     * an 8-byte, big-endian value and padded on the left with four 0x00 bytes.
     * 2. The padded sequence number is XORed with the client_write_IV (when the
     * client is sending) or server_write_IV (when the server is sending).
     */
    private byte[] calculateRFC7905Iv(byte[] nonce, byte[] iv) {
        byte[] padding = new byte[] { 0x00, 0x00, 0x00, 0x00 };
        long nonceLong = ArrayConverter.bytesToLong(nonce);
        byte[] temp = ArrayConverter.concatenate(padding, ArrayConverter.longToUint64Bytes(nonceLong),
                (RecordAEADCipher.AEAD_IV_LENGTH - padding.length));

        for (int i = 0; i < RecordAEADCipher.AEAD_IV_LENGTH; ++i) {
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
        throw new UnsupportedOperationException("ChaCha20Poly1305 can only be used as an AEAD Cipher!");
    }

    @Override
    public byte[] decrypt(byte[] iv, int tagLength, byte[] someBytes) {
        throw new UnsupportedOperationException("ChaCha20Poly1305 can only be used as an AEAD Cipher!");
    }

    @Override
    public byte[] decrypt(byte[] iv, int tagLength, byte[] additionAuthenticatedData, byte[] someBytes) {
        this.cipher.init(false, new ParametersWithIV(new KeyParameter(this.key, 0, this.key.length), this.ZEROES, 0,
                RecordAEADCipher.AEAD_IV_LENGTH));
        additionalDataLength = additionAuthenticatedData.length;
        int ciphertextLength = someBytes.length - RecordAEADCipher.AEAD_TAG_LENGTH;
        byte[] plaintext = new byte[getOutputSize(false, someBytes.length)];

        int concatIvLength = iv.length;
        byte[] nonce = Arrays.copyOfRange(iv, (concatIvLength - RecordAEADCipher.SEQUENCE_NUMBER_LENGTH),
                concatIvLength);
        byte[] readIv = Arrays.copyOfRange(iv, 0, (concatIvLength - RecordAEADCipher.SEQUENCE_NUMBER_LENGTH));
        byte[] rfc7905Iv = calculateRFC7905Iv(nonce, readIv);

        this.cipher.init(false, new ParametersWithIV(null, rfc7905Iv));
        initMAC();
        updateMAC(additionAuthenticatedData, 0, additionalDataLength);
        updateMAC(someBytes, 0, ciphertextLength);

        byte[] aadLengthLittleEndian = ArrayConverter.reverseByteOrder(ArrayConverter.longToBytes(
                Long.valueOf(additionalDataLength), 8));
        byte[] ciphertextLengthLittleEndian = ArrayConverter.reverseByteOrder(ArrayConverter.longToBytes(
                Long.valueOf(ciphertextLength), 8));

        byte[] calculatedMAC = ArrayConverter.concatenate(aadLengthLittleEndian, ciphertextLengthLittleEndian, 8);
        this.mac.update(calculatedMAC, 0, RecordAEADCipher.AEAD_TAG_LENGTH);
        this.mac.doFinal(calculatedMAC, 0);

        byte[] receivedMAC = Arrays.copyOfRange(someBytes, ciphertextLength, someBytes.length);
        if (!Arrays.areEqual(calculatedMAC, receivedMAC)) {
            LOGGER.warn("MAC verification failed, continuing anyways.");
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
        int concatIvLength = iv.length;
        byte[] nonce = Arrays.copyOfRange(iv, (concatIvLength - RecordAEADCipher.SEQUENCE_NUMBER_LENGTH),
                concatIvLength);
        byte[] writeIv = Arrays.copyOfRange(iv, 0, (concatIvLength - RecordAEADCipher.SEQUENCE_NUMBER_LENGTH));
        this.cipher.init(true, new ParametersWithIV(new KeyParameter(this.key, 0, this.key.length), this.ZEROES, 0,
                RecordAEADCipher.AEAD_IV_LENGTH));
        int additionalDataLength = additionAuthenticatedData.length;
        int plaintextLength = someBytes.length;
        byte[] ciphertext = new byte[getOutputSize(true, plaintextLength)];
        byte[] rfc7905Iv = calculateRFC7905Iv(nonce, writeIv);

        this.cipher.init(true, new ParametersWithIV(null, rfc7905Iv));
        initMAC();
        updateMAC(additionAuthenticatedData, 0, additionalDataLength);
        cipher.processBytes(someBytes, 0, plaintextLength, ciphertext, 0);

        updateMAC(ciphertext, 0, plaintextLength);

        byte[] aadLengthLittleEndian = ArrayConverter.reverseByteOrder(ArrayConverter.longToBytes(
                Long.valueOf(additionalDataLength), 8));
        byte[] plaintextLengthLittleEndian = ArrayConverter.reverseByteOrder(ArrayConverter.longToBytes(
                Long.valueOf(plaintextLength), 8));
        byte[] aadPlaintextLengthsLittleEndian = ArrayConverter.concatenate(aadLengthLittleEndian,
                plaintextLengthLittleEndian, 8);

        mac.update(aadPlaintextLengthsLittleEndian, 0, RecordAEADCipher.AEAD_TAG_LENGTH);
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

    private int getOutputSize(boolean isEncrypting, int inputLength) {
        return isEncrypting ? inputLength + RecordAEADCipher.AEAD_TAG_LENGTH : inputLength
                - RecordAEADCipher.AEAD_TAG_LENGTH;
    }

    private void initMAC() {
        byte[] firstBlock = new byte[64];
        this.cipher.processBytes(firstBlock, 0, 64, firstBlock, 0);
        this.mac.init(new KeyParameter(firstBlock, 0, 32));
    }

    @Override
    public void setIv(byte[] iv) {
        throw new UnsupportedOperationException("The IV has to be passed with the encrypt() call!");
    }

    private void updateMAC(byte[] buf, int off, int len) {
        this.mac.update(buf, off, len);

        int partial = len % RecordAEADCipher.AEAD_TAG_LENGTH;
        if (partial != 0) {
            this.mac.update(this.ZEROES, 0, RecordAEADCipher.AEAD_TAG_LENGTH - partial);
        }
    }
}
