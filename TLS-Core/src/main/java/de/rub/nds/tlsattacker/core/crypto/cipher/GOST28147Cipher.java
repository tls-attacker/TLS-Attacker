/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.cipher;

import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jcajce.spec.GOST28147ParameterSpec;

/**
 * GOST 28147-89 counter mode as defined in RFC 5830 with CryptoPro key meshing
 * as defined in RFC 4357.
 */
public class GOST28147Cipher implements EncryptionCipher, DecryptionCipher {

    private static final byte[] C = { (byte) 0x69, (byte) 0x00, (byte) 0x72, (byte) 0x22, (byte) 0x64, (byte) 0xC9,
            (byte) 0x04, (byte) 0x23, (byte) 0x8D, (byte) 0x3A, (byte) 0xDB, (byte) 0x96, (byte) 0x46, (byte) 0xE9,
            (byte) 0x2A, (byte) 0xC4, (byte) 0x18, (byte) 0xFE, (byte) 0xAC, (byte) 0x94, (byte) 0x00, (byte) 0xED,
            (byte) 0x07, (byte) 0x12, (byte) 0xC0, (byte) 0x86, (byte) 0xDC, (byte) 0xC2, (byte) 0xEF, (byte) 0x4C,
            (byte) 0xA9, (byte) 0x2B };

    public static final byte[] SBox_Z = { 0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF,
            0x1, 0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF, 0xB, 0x3, 0x5, 0x8,
            0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0, 0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7,
            0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB, 0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4,
            0x2, 0xC, 0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0, 0x8, 0xE, 0x2,
            0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7, 0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3,
            0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2 };

    private int keyCount;

    private byte[] key;
    private byte[] state;
    private byte[] keyStream;

    private final Cipher cipher;
    private final CipherAlgorithm algorithm;
    private final GOST28147ParameterSpec spec;

    public GOST28147Cipher(CipherAlgorithm algorithm, GOST28147ParameterSpec spec, byte[] key, byte[] iv) {
        this.algorithm = algorithm;
        this.spec = spec;
        this.key = key;
        this.state = iv;

        try {
            cipher = Cipher.getInstance(algorithm.getJavaName());
            initCipher(Cipher.ENCRYPT_MODE);
        } catch (GeneralSecurityException e) {
            throw new UnsupportedOperationException("Could not initialize cipher " + algorithm + "!");
        }
    }

    private void initCipher(int mode) throws GeneralSecurityException {
        cipher.init(mode, new SecretKeySpec(key, algorithm.getJavaName()), spec);
    }

    private byte getKeyByte() throws GeneralSecurityException {
        if (keyCount % 8 == 0) {
            if (keyCount == 1024) {
                keyCount = 0;
                mesh();
            }

            if (keyCount == 0) {
                state = cipher.doFinal(state);
            }

            increment();
            keyStream = cipher.doFinal(state);
        }

        return keyStream[keyCount++ % 8];
    }

    private void increment() {
        ByteBuffer wrappedIv = ByteBuffer.wrap(state);
        wrappedIv.order(ByteOrder.LITTLE_ENDIAN);
        int y = wrappedIv.getInt();
        int z = wrappedIv.getInt();

        y += 0x01010101; // C2
        int zTemp = z + 0x01010104; // C1
        z = zTemp >= 0 && z < 0 ? zTemp + 1 : zTemp;

        wrappedIv.putInt(0, y);
        wrappedIv.putInt(4, z);
    }

    private void mesh() throws GeneralSecurityException {
        initCipher(Cipher.DECRYPT_MODE);
        key = cipher.doFinal(C);

        initCipher(Cipher.ENCRYPT_MODE);
        state = cipher.doFinal(state);
    }

    @Override
    public byte[] encrypt(byte[] someBytes) throws CryptoException {
        try {
            byte[] encrypted = new byte[someBytes.length];
            for (int i = 0; i < someBytes.length; i++) {
                encrypted[i] = (byte) (getKeyByte() ^ someBytes[i]);
            }
            return encrypted;
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Could not generate next key byte!", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] someBytes) throws CryptoException {
        return encrypt(someBytes);
    }

    @Override
    public byte[] encrypt(byte[] iv, byte[] someBytes) {
        throw new UnsupportedOperationException("Can only be used as a stream cipher!");
    }

    @Override
    public byte[] decrypt(byte[] iv, byte[] someBytes) {
        return encrypt(iv, someBytes);
    }

    @Override
    public byte[] encrypt(byte[] iv, int tagLength, byte[] someBytes) {
        throw new UnsupportedOperationException("Can only be used as a stream cipher!");
    }

    @Override
    public byte[] decrypt(byte[] iv, int tagLength, byte[] someBytes) {
        return encrypt(iv, tagLength, someBytes);
    }

    @Override
    public byte[] encrypt(byte[] iv, int tagLength, byte[] additionAuthenticatedData, byte[] someBytes) {
        throw new UnsupportedOperationException("Can only be used as a stream cipher!");
    }

    @Override
    public byte[] decrypt(byte[] iv, int tagLength, byte[] additionAuthenticatedData, byte[] someBytes) {
        return encrypt(iv, tagLength, additionAuthenticatedData, someBytes);
    }

    @Override
    public int getBlocksize() {
        throw new UnsupportedOperationException("Can only be used as a stream cipher!");
    }

    @Override
    public byte[] getIv() {
        throw new UnsupportedOperationException("Can only be used as a stream cipher!");
    }

    @Override
    public void setIv(byte[] iv) {
        throw new UnsupportedOperationException("Can only be used as a stream cipher!");
    }

}
