/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.gost;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.modes.GCFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.ParametersWithSBox;
import org.bouncycastle.crypto.params.ParametersWithUKM;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/*
 * LICENSE
 * Copyright (c) 2000 - 2018 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)
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
    private GOST28147Engine cipher = new GOST28147Engine();
    private GOST28147Mac mac = new GOST28147Mac();

    public void init(boolean forWrapping, CipherParameters param) {
        if (param instanceof ParametersWithRandom) {
            ParametersWithRandom pr = (ParametersWithRandom) param;
            param = pr.getParameters();
        }

        ParametersWithUKM pU = (ParametersWithUKM) param;

        byte[] sBox = null;
        KeyParameter kParam;

        if (pU.getParameters() instanceof ParametersWithSBox) {
            kParam = (KeyParameter) ((ParametersWithSBox) pU.getParameters()).getParameters();
            sBox = ((ParametersWithSBox) pU.getParameters()).getSBox();
        } else {
            kParam = (KeyParameter) pU.getParameters();
        }

        kParam = new KeyParameter(cryptoProDiversify(kParam.getKey(), pU.getUKM(), sBox));
        CipherParameters cU;

        if (sBox != null) {
            cU = new ParametersWithSBox(kParam, sBox);
        } else {
            cU = kParam;
        }

        cipher.init(forWrapping, cU);
        mac.init(new ParametersWithIV(cU, pU.getUKM()));
    }

    public String getAlgorithmName() {
        return "GOST28147Wrap";
    }

    public byte[] wrap(byte[] input, int inOff, int inLen) {
        mac.update(input, inOff, inLen);

        byte[] wrappedKey = new byte[inLen + mac.getMacSize()];

        cipher.processBlock(input, inOff, wrappedKey, 0);
        cipher.processBlock(input, inOff + 8, wrappedKey, 8);
        cipher.processBlock(input, inOff + 16, wrappedKey, 16);
        cipher.processBlock(input, inOff + 24, wrappedKey, 24);

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

    /*
     * RFC 4357 6.5. CryptoPro KEK Diversification Algorithm Given a random
     * 64-bit UKM and a GOST 28147-89 key K, this algorithm creates a new GOST
     * 28147-89 key K(UKM). 1) Let K[0] = K; 2) UKM is split into components
     * a[i,j]: UKM = a[0]|..|a[7] (a[i] - byte, a[i,0]..a[i,7] - it's bits) 3)
     * Let i be 0. 4) K[1]..K[8] are calculated by repeating the following
     * algorithm eight times: A) K[i] is split into components k[i,j]: K[i] =
     * k[i,0]|k[i,1]|..|k[i,7] (k[i,j] - 32-bit integer) B) Vector S[i] is
     * calculated: S[i] = ((a[i,0]*k[i,0] + ... + a[i,7]*k[i,7]) mod 2^32) |
     * (((~a[i,0])*k[i,0] + ... + (~a[i,7])*k[i,7]) mod 2^32); C) K[i+1] =
     * encryptCFB (S[i], K[i], K[i]) D) i = i + 1 5) Let K(UKM) be K[8].
     */
    private static byte[] cryptoProDiversify(byte[] K, byte[] ukm, byte[] sBox) {
        for (int i = 0; i != 8; i++) {
            int sOn = 0;
            int sOff = 0;
            for (int j = 0; j != 8; j++) {
                int kj = Pack.littleEndianToInt(K, j * 4);
                if (bitSet(ukm[i], j)) {
                    sOn += kj;
                } else {
                    sOff += kj;
                }
            }

            byte[] s = new byte[8];
            Pack.intToLittleEndian(sOn, s, 0);
            Pack.intToLittleEndian(sOff, s, 4);

            GCFBBlockCipher c = new GCFBBlockCipher(new GOST28147Engine());

            c.init(true, new ParametersWithIV(new ParametersWithSBox(new KeyParameter(K), sBox), s));

            c.processBlock(K, 0, K, 0);
            c.processBlock(K, 8, K, 8);
            c.processBlock(K, 16, K, 16);
            c.processBlock(K, 24, K, 24);
        }

        return K;
    }

    private static boolean bitSet(byte v, int bitNo) {
        return (v & (1 << bitNo)) != 0;
    }

}
