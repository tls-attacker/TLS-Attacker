/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
/**
 * TLS-AEAD-Cipher "Chacha20Poly1305", based on BouncyCastle's class
 * "BcChaCha20Poly1305".
 * See RFC7905 for further information.
 */

package de.rub.nds.tlsattacker.core.crypto.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.Bits;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.engines.Salsa20Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public abstract class ChaCha20Poly1305Cipher extends BaseCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    private final byte[] key;

    private static final int TAG_LENGTH = 16;

    private static final byte[] ZEROES = new byte[TAG_LENGTH - 1];

    private boolean draftStructure;

    private Salsa20Engine cipher;

    private final Poly1305 mac = new Poly1305();

    protected final int IV_LENGTH;

    public ChaCha20Poly1305Cipher(byte[] key, int ivLength) {
        if (key.length != 32) {
            LOGGER.warn("Key for ChaCha20Poly1305 has wrong size. Expected 32 byte but found: " + key.length
                + ". Padding/Trimming to 32 Byte.");
            if (key.length > 32) {
                key = Arrays.copyOfRange(key, 0, 32);
            } else {
                byte[] tempKey = new byte[32];
                for (int i = 0; i < key.length; i++) {
                    tempKey[i] = key[i];
                }
                key = tempKey;
            }
        }
        this.key = key;
        this.IV_LENGTH = ivLength;
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
    public byte[] decrypt(byte[] iv, int tagLength, byte[] additionalAuthenticatedData, byte[] ciphertext)
        throws CryptoException {
        this.cipher.init(false, new ParametersWithIV(new KeyParameter(this.key, 0, this.key.length),
            new byte[(tagLength / Bits.IN_A_BYTE) - 1], 0, iv.length));
        int additionalDataLength = additionalAuthenticatedData.length;
        int ciphertextLength = ciphertext.length - (tagLength / Bits.IN_A_BYTE);

        byte[] plaintext = new byte[getOutputSize(false, ciphertext.length)];
        byte[] aadLengthLittleEndian =
            ArrayConverter.reverseByteOrder(ArrayConverter.longToBytes(Long.valueOf(additionalDataLength), 8));
        byte[] ciphertextLengthLittleEndian =
            ArrayConverter.reverseByteOrder(ArrayConverter.longToBytes(Long.valueOf(ciphertextLength), 8));

        this.cipher.init(false, new ParametersWithIV(null, iv));
        initMAC();
        byte[] calculatedMAC = new byte[16];

        if (draftStructure) {
            byte[] macInput = ArrayConverter.concatenate(additionalAuthenticatedData, aadLengthLittleEndian);
            macInput = ArrayConverter.concatenate(macInput, ciphertext, ciphertextLength);
            macInput = ArrayConverter.concatenate(macInput, ciphertextLengthLittleEndian);
            this.mac.update(macInput, 0, macInput.length);
            this.mac.doFinal(calculatedMAC, 0);
        } else {
            updateMAC(additionalAuthenticatedData, 0, additionalDataLength);
            updateMAC(ciphertext, 0, ciphertextLength);
            calculatedMAC = ArrayConverter.concatenate(aadLengthLittleEndian, ciphertextLengthLittleEndian, 8);
            this.mac.update(calculatedMAC, 0, (tagLength / Bits.IN_A_BYTE));
            this.mac.doFinal(calculatedMAC, 0);
        }

        byte[] receivedMAC = Arrays.copyOfRange(ciphertext, ciphertextLength, ciphertext.length);
        if (!Arrays.areEqual(calculatedMAC, receivedMAC)) {
            LOGGER.warn("MAC verification failed");
            throw new CryptoException();
        }
        this.cipher.processBytes(ciphertext, 0, ciphertextLength, plaintext, 0);

        return plaintext;
    }

    @Override
    public byte[] encrypt(byte[] iv, int tagLength, byte[] additionAuthenticatedData, byte[] someBytes) {
        if (iv.length != IV_LENGTH) {
            LOGGER.warn("IV for ChaCha20Poly1305 has wrong size. Expected " + IV_LENGTH + " byte but found: "
                + iv.length + ". Padding/Trimming to " + IV_LENGTH + " Byte.");
            if (iv.length > IV_LENGTH) {
                iv = Arrays.copyOfRange(iv, 0, IV_LENGTH);
            } else {
                byte[] tempIv = new byte[IV_LENGTH];
                for (int i = 0; i < iv.length; i++) {
                    tempIv[i] = iv[i];
                }
                iv = tempIv;
            }
        }
        this.cipher.init(true, new ParametersWithIV(new KeyParameter(this.key, 0, this.key.length),
            new byte[(tagLength / Bits.IN_A_BYTE) - 1], 0, iv.length));
        int additionalDataLength = additionAuthenticatedData.length;
        int plaintextLength = someBytes.length;
        byte[] ciphertext = new byte[getOutputSize(true, plaintextLength)];
        this.cipher.init(true, new ParametersWithIV(null, iv));
        initMAC();
        cipher.processBytes(someBytes, 0, plaintextLength, ciphertext, 0);

        byte[] aadLengthLittleEndian =
            ArrayConverter.reverseByteOrder(ArrayConverter.longToBytes(Long.valueOf(additionalDataLength), 8));
        byte[] plaintextLengthLittleEndian =
            ArrayConverter.reverseByteOrder(ArrayConverter.longToBytes(Long.valueOf(plaintextLength), 8));
        byte[] aadPlaintextLengthsLittleEndian =
            ArrayConverter.concatenate(aadLengthLittleEndian, plaintextLengthLittleEndian, 8);

        if (draftStructure) {
            byte[] macInput = ArrayConverter.concatenate(additionAuthenticatedData, aadLengthLittleEndian);
            macInput = ArrayConverter.concatenate(macInput, ciphertext, plaintextLength);
            macInput = ArrayConverter.concatenate(macInput, plaintextLengthLittleEndian);
            mac.update(macInput, 0, macInput.length);
            mac.doFinal(ciphertext, 0 + plaintextLength);
        } else {
            updateMAC(additionAuthenticatedData, 0, additionalDataLength);
            updateMAC(ciphertext, 0, plaintextLength);
            mac.update(aadPlaintextLengthsLittleEndian, 0, (tagLength / Bits.IN_A_BYTE));
            mac.doFinal(ciphertext, 0 + plaintextLength);
        }
        return ciphertext;
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
    public int getBlocksize() {
        throw new UnsupportedOperationException("ChaCha20Poly1305 can only be used as an AEAD Cipher!");
    }

    @Override
    public byte[] getIv() {
        throw new UnsupportedOperationException();
    }

    private int getOutputSize(boolean isEncrypting, int inputLength) {
        return isEncrypting ? inputLength + TAG_LENGTH : inputLength - TAG_LENGTH;
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

        int partial = len % TAG_LENGTH;
        if (partial != 0) {
            this.mac.update(this.ZEROES, 0, TAG_LENGTH - partial);
        }
    }

    public void setCipher(Salsa20Engine cipher) {
        this.cipher = cipher;
    }

    public boolean isDraftStructure() {
        return draftStructure;
    }

    public void setDraftStructure(boolean draftStructure) {
        this.draftStructure = draftStructure;
    }

}
