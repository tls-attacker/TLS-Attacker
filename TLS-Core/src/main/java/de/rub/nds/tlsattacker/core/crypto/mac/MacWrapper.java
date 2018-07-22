/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.mac;

import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.macs.HMac;

public class MacWrapper {

    public static WrappedMac getMac(MacAlgorithm macAlg, byte[] key) throws NoSuchAlgorithmException {
        if (macAlg == MacAlgorithm.HMAC_GOSTR3411) {
            GOST3411Digest digest = new GOST3411Digest();
            return new ContinuousMac(new HMac(digest), digest, key);
        } else if (macAlg == MacAlgorithm.IMIT_GOST28147) {
            return new ContinuousMac(new GOST28147Mac(), key);
        } else if (macAlg.getJavaName() != null) {
            return new JavaMac(macAlg.getJavaName(), key);
        } else {
            throw new NoSuchAlgorithmException("Mac: " + macAlg + " is not supported!");
        }
    }

}
