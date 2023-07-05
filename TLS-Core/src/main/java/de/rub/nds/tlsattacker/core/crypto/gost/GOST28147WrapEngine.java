/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto.gost;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.modes.GCFBBlockCipher;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

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
public class GOST28147WrapEngine implements Wrapper {

    private static final Logger LOGGER = LogManager.getLogger();

    /*
     * RFC 4357 6.5. CryptoPro KEK Diversification Algorithm Given a random 64-bit UKM and a GOST 28147-89 key key, this
     * algorithm creates a new GOST 28147-89 key key(UKM). 1) Let key[0] = key; 2) UKM is split into components a[i,j]:
     * UKM = a[0]|..|a[7] (a[i] - byte, a[i,0]..a[i,7] - it's bits) 3) Let i be 0. 4) key[1]..key[8] are calculated by
     * repeating the following algorithm eight times: A) key[i] is split into components k[i,j]: key[i] =
     * k[i,0]|k[i,1]|..|k[i,7] (k[i,j] - 32-bit integer) B) Vector S[i] is calculated: S[i] = ((a[i,0]*k[i,0] + ... +
     * a[i,7]*k[i,7]) mod 2^32) | (((~a[i,0])*k[i,0] + ... + (~a[i,7])*k[i,7]) mod 2^32); C) key[i+1] = encryptCFB
     * (S[i], key[i], key[i]) D) i = i + 1 5) Let key(UKM) be key[8].
     */
    private static byte[] cryptoProDiversify(byte[] key, byte[] ukm, byte[] sbox) {
        for (int i = 0; i != 8; i++) {
            int sboxOn = 0;
            int sboxOff = 0;
            for (int j = 0; j != 8; j++) {
                int kj = Pack.littleEndianToInt(key, j * 4);
                if (bitSet(ukm[i], j)) {
                    sboxOn += kj;
                } else {
                    sboxOff += kj;
                }
            }

            byte[] s = new byte[8];
            Pack.intToLittleEndian(sboxOn, s, 0);
            Pack.intToLittleEndian(sboxOff, s, 4);

            GCFBBlockCipher c = new GCFBBlockCipher(new GOST28147Engine());

            c.init(
                    true,
                    new ParametersWithIV(new ParametersWithSBox(new KeyParameter(key), sbox), s));

            c.processBlock(key, 0, key, 0);
            c.processBlock(key, 8, key, 8);
            c.processBlock(key, 16, key, 16);
            c.processBlock(key, 24, key, 24);
        }

        return key;
    }

    private static boolean bitSet(byte v, int bitNo) {
        return (v & (1 << bitNo)) != 0;
    }

    private GOST28147Engine cipher = new GOST28147Engine();
    private GOST28147Mac mac = new GOST28147Mac();

    public void init(boolean forWrapping, CipherParameters param) {
        if (param instanceof ParametersWithRandom) {
            ParametersWithRandom pr = (ParametersWithRandom) param;
            param = pr.getParameters();
        }

        ParametersWithUKM parametersWithUKM = (ParametersWithUKM) param;

        byte[] sbox = null;
        KeyParameter keyParameter;

        if (parametersWithUKM.getParameters() instanceof ParametersWithSBox) {
            keyParameter =
                    (KeyParameter)
                            ((ParametersWithSBox) parametersWithUKM.getParameters())
                                    .getParameters();
            sbox = ((ParametersWithSBox) parametersWithUKM.getParameters()).getSBox();
        } else {
            keyParameter = (KeyParameter) parametersWithUKM.getParameters();
        }

        keyParameter =
                new KeyParameter(
                        cryptoProDiversify(
                                keyParameter.getKey(), parametersWithUKM.getUKM(), sbox));
        CipherParameters cipherParameters;

        if (sbox != null) {
            cipherParameters = new ParametersWithSBox(keyParameter, sbox);
        } else {
            cipherParameters = keyParameter;
        }

        cipher.init(forWrapping, cipherParameters);
        mac.init(new ParametersWithIV(cipherParameters, parametersWithUKM.getUKM()));
    }

    public String getAlgorithmName() {
        return "GOST28147Wrap";
    }

    public byte[] wrap(byte[] input, int inOff, int inLen) {
        mac.update(input, inOff, inLen);

        byte[] wrappedKey = new byte[inLen + mac.getMacSize()];
        try {
            cipher.processBlock(input, inOff, wrappedKey, 0);
            cipher.processBlock(input, inOff + 8, wrappedKey, 8);
            cipher.processBlock(input, inOff + 16, wrappedKey, 16);
            cipher.processBlock(input, inOff + 24, wrappedKey, 24);
        } catch (Exception e) {
            LOGGER.warn("Could not wrap key. Continuing with partially wrapped key", e);
        }
        mac.doFinal(wrappedKey, inLen);

        return wrappedKey;
    }

    public byte[] unwrap(byte[] input, int inOff, int inLen) {
        byte[] decKey = new byte[inLen - mac.getMacSize()];

        cipher.processBlock(input, inOff, decKey, 0);
        cipher.processBlock(input, inOff + 8, decKey, 8);
        cipher.processBlock(input, inOff + 16, decKey, 16);
        cipher.processBlock(input, inOff + 24, decKey, 24);

        byte[] macResult = new byte[mac.getMacSize()];

        mac.update(decKey, 0, decKey.length);

        mac.doFinal(macResult, 0);

        byte[] macExpected = new byte[mac.getMacSize()];

        System.arraycopy(input, inOff + inLen - 4, macExpected, 0, mac.getMacSize());

        if (!Arrays.constantTimeAreEqual(macResult, macExpected)) {
            throw new IllegalStateException("mac mismatch");
        }

        return decKey;
    }
}
