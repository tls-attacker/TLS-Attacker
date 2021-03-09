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
import java.util.concurrent.Callable;

/**
 * Callable to brute-force the 5 random bytes when checking whether a server is vulnerable to the "leaky export" oracle
 * DROWN attack.
 */
class LeakyExportCheckCallable implements Callable<Boolean> {

    private int firstByteFrom;
    private int firstByteTo;
    private volatile int processedSecondBytes;
    private LeakyExportCheckData data;

    public LeakyExportCheckCallable(int firstByteFrom, int firstByteTo, LeakyExportCheckData data) {
        this.firstByteFrom = firstByteFrom;
        this.firstByteTo = firstByteTo;
        this.processedSecondBytes = 0;
        this.data = data;
    }

    public int getProcessedSecondBytes() {
        return processedSecondBytes;
    }

    @Override
    public Boolean call() {
        byte[] masterKey = new byte[data.getClearKey().length + data.getCipherSuite().getSecretKeyByteNumber()];
        System.arraycopy(data.getClearKey(), 0, masterKey, 0, data.getClearKey().length);

        int secretKeyBytesUsed =
            Math.min(data.getSecretKeyPlain().length, data.getCipherSuite().getSecretKeyByteNumber());
        System.arraycopy(data.getSecretKeyPlain(), 0, masterKey, data.getClearKey().length, secretKeyBytesUsed);
        if (secretKeyBytesUsed < data.getCipherSuite().getSecretKeyByteNumber()) {
            // TODO: Check this, the paper is weird
            System.arraycopy(data.getSecretKeyEnc(), secretKeyBytesUsed, masterKey,
                data.getClearKey().length + secretKeyBytesUsed,
                data.getCipherSuite().getSecretKeyByteNumber() - secretKeyBytesUsed);
        }

        // Use ints for iteration because otherwise the loop condition will be
        // affected by wrap-arounds
        for (int a = firstByteFrom; a < firstByteTo; a++) {
            masterKey[0] = (byte) a;
            for (int b = -128; b < 128; b++) {
                masterKey[1] = (byte) b;
                for (int c = -128; c < 128; c++) {
                    masterKey[2] = (byte) c;
                    for (int d = -128; d < 128; d++) {
                        masterKey[3] = (byte) d;
                        for (int e = -128; e < 128; e++) {
                            if (Thread.currentThread().isInterrupted()) {
                                return false;
                            }

                            masterKey[4] = (byte) e;
                            if (checkMasterKey(masterKey)) {
                                return true;
                            }
                        }
                    }
                }
                processedSecondBytes++;
            }
        }

        return false;
    }

    private boolean checkMasterKey(byte[] masterKey) {
        byte[] clientReadKey =
            ServerVerifyChecker.makeKeyMaterial(masterKey, data.getClientRandom(), data.getServerRandom(), "0");
        byte[] decrypted;

        if (data.getCipherSuite() == SSL2CipherSuite.SSL_CK_RC4_128_EXPORT40_WITH_MD5) {
            decrypted = ServerVerifyChecker.decryptRC4(clientReadKey, data.getEncrypted());
        } else {
            // SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
            decrypted = ServerVerifyChecker.decryptRC2(clientReadKey, data.getEncrypted(), data.getIv(),
                data.getPaddingLength());
        }

        return ServerVerifyChecker.compareDecrypted(decrypted, data.getClientRandom(), true);
    }

}
