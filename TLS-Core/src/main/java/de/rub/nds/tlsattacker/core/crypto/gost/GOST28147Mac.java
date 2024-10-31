/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto.gost;

import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.cipher.GOST28147Cipher;
import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithSBox;
import org.bouncycastle.jcajce.spec.GOST28147ParameterSpec;
import org.bouncycastle.util.Memoable;

/*
 * LICENSE
 * <p>Copyright (c) 2000 - 2018 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 * BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
public class GOST28147Mac implements Mac, Memoable {
    private int blockSize = 8;
    private int macSize = 4;
    private int bufOff;
    private int processedBytes;
    private byte[] buf;
    private byte[] mac;
    private boolean firstStep = true;
    private byte[] key;
    private int[] workingKey = null;
    private byte[] macIV = null;
    private final Cipher meshCipher;

    //
    // This is default S-box - E_A.
    private byte[] sbox = {
        0x9, 0x6, 0x3, 0x2, 0x8, 0xB, 0x1, 0x7, 0xA, 0x4, 0xE, 0xF, 0xC, 0x0, 0xD, 0x5, 0x3, 0x7,
        0xE, 0x9, 0x8, 0xA, 0xF, 0x0, 0x5, 0x2, 0x6, 0xC, 0xB, 0x4, 0xD, 0x1, 0xE, 0x4, 0x6, 0x2,
        0xB, 0x3, 0xD, 0x8, 0xC, 0xF, 0x5, 0xA, 0x0, 0x7, 0x1, 0x9, 0xE, 0x7, 0xA, 0xC, 0xD, 0x1,
        0x3, 0x9, 0x0, 0x2, 0xB, 0x4, 0xF, 0x8, 0x5, 0x6, 0xB, 0x5, 0x1, 0x9, 0x8, 0xD, 0xF, 0x0,
        0xE, 0x4, 0x2, 0x3, 0xC, 0x7, 0xA, 0x6, 0x3, 0xA, 0xD, 0xC, 0x1, 0x2, 0x0, 0xB, 0x7, 0x5,
        0x9, 0x4, 0x8, 0xF, 0xE, 0x6, 0x1, 0xD, 0x2, 0x9, 0x7, 0xA, 0x6, 0x0, 0x8, 0xC, 0x4, 0x5,
        0xF, 0x3, 0xB, 0xE, 0xB, 0xA, 0xF, 0x5, 0x0, 0xC, 0xE, 0x8, 0x6, 0x2, 0x3, 0x9, 0x1, 0x7,
        0xD, 0x4
    };

    public GOST28147Mac() {
        mac = new byte[blockSize];
        buf = new byte[blockSize];
        key = new byte[32];

        try {
            meshCipher = Cipher.getInstance(CipherAlgorithm.GOST_28147_CNT.getJavaName());
        } catch (GeneralSecurityException e) {
            throw new UnsupportedOperationException("Could not initialize mesh cipher!");
        }
    }

    private GOST28147Mac(GOST28147Mac mac) {
        this();

        reset(mac);
    }

    private int[] generateWorkingKey(byte[] userKey) {
        if (userKey.length != 32) {
            throw new IllegalArgumentException(
                    "Key length invalid. Key needs to be 32 byte - 256 bit!!!");
        }

        int[] key = new int[8];
        for (int i = 0; i != 8; i++) {
            key[i] = bytesToInt(userKey, i * 4);
        }

        return key;
    }

    public void init(CipherParameters params) throws IllegalArgumentException {
        reset();
        buf = new byte[blockSize];
        macIV = null;

        if (params instanceof ParametersWithIV) {
            ParametersWithIV param = (ParametersWithIV) params;

            System.arraycopy(param.getIV(), 0, mac, 0, mac.length);
            macIV = param.getIV(); // don't skip the initial CM5Func

            params = param.getParameters();
        }

        if (params instanceof ParametersWithSBox) {
            ParametersWithSBox param = (ParametersWithSBox) params;
            System.arraycopy(param.getSBox(), 0, this.sbox, 0, param.getSBox().length);
            params = param.getParameters();
        }

        if (params instanceof KeyParameter) {
            key = ((KeyParameter) params).getKey();
            workingKey = generateWorkingKey(key);
        } else {
            throw new IllegalArgumentException(
                    "invalid parameter passed to GOST28147 init - " + params.getClass().getName());
        }
    }

    public String getAlgorithmName() {
        return "GOST28147Mac";
    }

    public int getMacSize() {
        return macSize;
    }

    private int gost28147_mainStep(int n1, int key) {
        int cm = (key + n1); // CM1

        // S-box replacing

        int om = sbox[0 + ((cm >> (0 * 4)) & 0xF)] << (0 * 4);
        om += sbox[16 + ((cm >> (1 * 4)) & 0xF)] << (1 * 4);
        om += sbox[32 + ((cm >> (2 * 4)) & 0xF)] << (2 * 4);
        om += sbox[48 + ((cm >> (3 * 4)) & 0xF)] << (3 * 4);
        om += sbox[64 + ((cm >> (4 * 4)) & 0xF)] << (4 * 4);
        om += sbox[80 + ((cm >> (5 * 4)) & 0xF)] << (5 * 4);
        om += sbox[96 + ((cm >> (6 * 4)) & 0xF)] << (6 * 4);
        om += sbox[112 + ((cm >> (7 * 4)) & 0xF)] << (7 * 4);

        return om << 11 | om >>> (32 - 11); // 11-leftshift
    }

    private void gost28147MacFunc(byte[] in, byte[] out) {
        if (processedBytes == 1024) {
            processedBytes = 0;
            try {
                SecretKeySpec spec = new SecretKeySpec(key, meshCipher.getAlgorithm());
                meshCipher.init(Cipher.DECRYPT_MODE, spec, new GOST28147ParameterSpec(sbox));
                key = meshCipher.doFinal(GOST28147Cipher.getC());
                workingKey = generateWorkingKey(key);
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("Could not mesh key!");
            }
        }
        processedBytes += 8;

        int n1;
        int n2;
        int tmp; // tmp -> for saving n1
        n1 = bytesToInt(in, 0);
        n2 = bytesToInt(in, 4);

        // 1-16 steps
        for (int k = 0; k < 2; k++) {
            for (int j = 0; j < 8; j++) {
                tmp = n1;
                n1 = n2 ^ gost28147_mainStep(n1, workingKey[j]); // CM2
                n2 = tmp;
            }
        }

        intToBytes(n1, out, 0);
        intToBytes(n2, out, 4);
    }

    // array of bytes to type int
    private int bytesToInt(byte[] in, int inOff) {
        return ((in[inOff + 3] << 24) & 0xff000000)
                + ((in[inOff + 2] << 16) & 0xff0000)
                + ((in[inOff + 1] << 8) & 0xff00)
                + (in[inOff] & 0xff);
    }

    // int to array of bytes
    private void intToBytes(int num, byte[] out, int outOff) {
        out[outOff + 3] = (byte) (num >>> 24);
        out[outOff + 2] = (byte) (num >>> 16);
        out[outOff + 1] = (byte) (num >>> 8);
        out[outOff] = (byte) num;
    }

    private byte[] cm5Func(byte[] buf, int bufOff, byte[] mac) {
        byte[] sum = new byte[buf.length - bufOff];

        System.arraycopy(buf, bufOff, sum, 0, mac.length);

        for (int i = 0; i != mac.length; i++) {
            sum[i] = (byte) (sum[i] ^ mac[i]);
        }

        return sum;
    }

    public void update(byte in) throws IllegalStateException {
        if (bufOff == buf.length) {
            byte[] sumbuf = new byte[buf.length];
            System.arraycopy(buf, 0, sumbuf, 0, mac.length);

            if (firstStep) {
                firstStep = false;
                if (macIV != null) {
                    sumbuf = cm5Func(buf, 0, macIV);
                }
            } else {
                sumbuf = cm5Func(buf, 0, mac);
            }

            gost28147MacFunc(sumbuf, mac);
            bufOff = 0;
        }

        buf[bufOff++] = in;
    }

    public void update(byte[] in, int inOff, int len)
            throws DataLengthException, IllegalStateException {
        if (len < 0) {
            throw new IllegalArgumentException("Can't have a negative input length!");
        }

        int gapLen = blockSize - bufOff;

        if (len > gapLen) {
            System.arraycopy(in, inOff, buf, bufOff, gapLen);

            byte[] sumbuf = new byte[buf.length];
            System.arraycopy(buf, 0, sumbuf, 0, mac.length);

            if (firstStep) {
                firstStep = false;
                if (macIV != null) {
                    sumbuf = cm5Func(buf, 0, macIV);
                }
            } else {
                sumbuf = cm5Func(buf, 0, mac);
            }

            gost28147MacFunc(sumbuf, mac);

            bufOff = 0;
            len -= gapLen;
            inOff += gapLen;

            while (len > blockSize) {
                sumbuf = cm5Func(in, inOff, mac);
                gost28147MacFunc(sumbuf, mac);

                len -= blockSize;
                inOff += blockSize;
            }
        }

        System.arraycopy(in, inOff, buf, bufOff, len);

        bufOff += len;
    }

    public int doFinal(byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        // padding with zero
        while (bufOff < blockSize) {
            buf[bufOff] = 0;
            bufOff++;
        }

        byte[] sumbuf = new byte[buf.length];
        System.arraycopy(buf, 0, sumbuf, 0, mac.length);

        if (firstStep) {
            firstStep = false;
        } else {
            sumbuf = cm5Func(buf, 0, mac);
        }

        gost28147MacFunc(sumbuf, mac);

        System.arraycopy(mac, (mac.length / 2) - macSize, out, outOff, macSize);

        reset();

        return macSize;
    }

    public void reset() {
        /*
         * clean the buffer.
         */
        for (int i = 0; i < buf.length; i++) {
            buf[i] = 0;
        }

        bufOff = 0;

        firstStep = true;
    }

    @Override
    public void reset(Memoable other) {
        GOST28147Mac t = (GOST28147Mac) other;

        bufOff = t.bufOff;
        firstStep = t.firstStep;
        processedBytes = t.processedBytes;

        System.arraycopy(t.buf, 0, buf, 0, t.buf.length);
        System.arraycopy(t.mac, 0, mac, 0, t.mac.length);
        System.arraycopy(t.sbox, 0, sbox, 0, t.sbox.length);

        if (t.key != null) {
            System.arraycopy(t.key, 0, key, 0, t.key.length);

            workingKey = generateWorkingKey(key);
        }

        if (t.macIV != null) {
            System.arraycopy(t.macIV, 0, macIV, 0, t.macIV.length);
        }
    }

    @Override
    public Memoable copy() {
        return new GOST28147Mac(this);
    }
}
