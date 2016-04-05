/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tls.crypto;

import de.rub.nds.tlsattacker.tls.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.tls.exceptions.CryptoException;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.tls.TlsUtils;

/**
 * Pseudo random function computation for TLS 1.0 - 1.2 (for TLS 1.0, bouncy
 * castle TlsUtils are used)
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public final class PseudoRandomFunction {

    /** master secret label */
    public static final String MASTER_SECRET_LABEL = "master secret";

    /** client finished label */
    public static final String CLIENT_FINISHED_LABEL = "client finished";

    /** server finished label */
    public static final String SERVER_FINISHED_LABEL = "server finished";

    /** key expansion label */
    public static final String KEY_EXPANSION_LABEL = "key expansion";

    private PseudoRandomFunction() {

    }

    /**
     * Computes PRF output of the provided size using the given mac algorithm
     * 
     * @param prfAlgorithm
     * @param secret
     * @param label
     * @param seed
     * @param size
     *            size of the output
     * @return
     */
    public static byte[] compute(PRFAlgorithm prfAlgorithm, byte[] secret, String label, byte[] seed, int size) {

	switch (prfAlgorithm) {
	    case TLS_PRF_SHA256:
	    case TLS_PRF_SHA384:
		return computeTls12(secret, label, seed, size, prfAlgorithm.getMacAlgorithm().getJavaName());
	    case TLS_PRF_LEGACY:
		// prf legacy is the prf computation function for older protocol
		// versions
		// it works by default with sha1 and md5
		return TlsUtils.PRF_legacy(secret, label, seed, size);
	    default:
		throw new UnsupportedOperationException("PRF computation for different"
			+ " protocol versions is not supported yet");
	}
    }

    /**
     * PRF computation for TLS 1.2
     * 
     * @param secret
     * @param label
     * @param seed
     * @param size
     * @param macAlgorithm
     * @return
     */
    private static byte[] computeTls12(byte[] secret, String label, byte[] seed, int size, String macAlgorithm) {
	try {
	    byte[] labelSeed = ArrayConverter.concatenate(label.getBytes(), seed);

	    SecretKeySpec keySpec = new SecretKeySpec(secret, macAlgorithm);
	    Mac mac = Mac.getInstance(macAlgorithm);
	    mac.init(keySpec);

	    byte[] out = new byte[0];

	    byte[] ai = labelSeed;
	    byte[] buf;
	    byte[] buf2;
	    while (out.length < size) {
		mac.update(ai);
		buf = mac.doFinal();
		ai = buf;
		mac.update(ai);
		mac.update(labelSeed);
		buf2 = mac.doFinal();
		out = ArrayConverter.concatenate(out, buf2);
	    }
	    return Arrays.copyOf(out, size);
	} catch (NoSuchAlgorithmException | InvalidKeyException ex) {
	    throw new CryptoException(ex);
	}
    }
}
