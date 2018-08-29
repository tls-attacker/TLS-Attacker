/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.mac;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.gost.GOST28147Mac;
import de.rub.nds.tlsattacker.core.util.GOSTUtils;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithSBox;

public class MacWrapper {

    public static WrappedMac getMac(ProtocolVersion version, CipherSuite cipherSuite, byte[] key)
            throws NoSuchAlgorithmException {
        MacAlgorithm macAlg = AlgorithmResolver.getMacAlgorithm(version, cipherSuite);
        if (macAlg == MacAlgorithm.HMAC_GOSTR3411) {
            GOST3411Digest digest = new GOST3411Digest();
            return new ContinuousMac(new HMac(digest), digest, new KeyParameter(key));
        } else if (macAlg == MacAlgorithm.HMAC_GOSTR3411_2012_256) {
            GOST3411_2012_256Digest digest = new GOST3411_2012_256Digest();
            return new ContinuousMac(new HMac(digest), digest, new KeyParameter(key));
        } else if (macAlg == MacAlgorithm.IMIT_GOST28147) {
            ParametersWithSBox parameters = new ParametersWithSBox(new KeyParameter(key),
                    GOSTUtils.getGostSBox(cipherSuite));
            return new ContinuousMac(new GOST28147Mac(), parameters);
        } else if (macAlg.getJavaName() != null) {
            return new JavaMac(macAlg.getJavaName(), key);
        } else {
            throw new NoSuchAlgorithmException("Mac: " + macAlg + " is not supported!");
        }
    }

}
