/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.impl.drown;

import de.rub.nds.tlsattacker.core.constants.SSL2CipherSuite;
import java.util.Arrays;

/**
 * Runnable for benchmarking the brute-force performance of ServerVerifyChecker in a multi-threaded setup.
 */
class LeakyExportBenchmarkRunnable implements Runnable {

    private int firstByteFrom;
    private int firstByteTo;
    private SSL2CipherSuite cipherSuite;
    private byte[] encrypted;
    private byte[] baseMasterKey;
    private byte[] challenge;
    private byte[] sessionId;
    private byte[] iv;

    public LeakyExportBenchmarkRunnable(SSL2CipherSuite cipherSuite, int firstByteFrom, int firstByteTo) {
        this.cipherSuite = cipherSuite;
        this.firstByteFrom = firstByteFrom;
        this.firstByteTo = firstByteTo;
    }

    public void init(byte[] encrypted, byte[] baseMasterKey, byte[] challenge, byte[] sessionId, byte[] iv) {
        this.encrypted = encrypted;
        this.baseMasterKey = baseMasterKey;
        this.challenge = challenge;
        this.sessionId = sessionId;
        this.iv = iv;
    }

    @Override
    public void run() {
        // Use ints for iteration because otherwise the loop condition will be
        // affected by wrap-arounds
        for (int a = firstByteFrom; a < firstByteTo; a++) {
            for (int b = -128; b < 128; b++) {
                for (int c = -128; c < 128; c++) {
                    byte[] masterKey = Arrays.copyOf(baseMasterKey, baseMasterKey.length);
                    masterKey[0] = (byte) a;
                    masterKey[1] = (byte) b;
                    masterKey[2] = (byte) c;
                    byte[] key = ServerVerifyChecker.makeKeyMaterial(masterKey, challenge, sessionId, "0");

                    if (cipherSuite == SSL2CipherSuite.SSL_CK_RC4_128_EXPORT40_WITH_MD5) {
                        ServerVerifyChecker.decryptRC4(key, encrypted);
                    } else if (cipherSuite == SSL2CipherSuite.SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5) {
                        ServerVerifyChecker.decryptRC2(key, encrypted, iv, 0);
                    }
                }
            }
        }
    }
}
