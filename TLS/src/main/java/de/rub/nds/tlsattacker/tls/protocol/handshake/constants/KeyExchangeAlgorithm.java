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
package de.rub.nds.tlsattacker.tls.protocol.handshake.constants;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public enum KeyExchangeAlgorithm {

    DHE_DSS,
    DHE_RSA,
    DH_ANON,
    RSA,
    DH_DSS,
    DH_RSA,
    EC_DIFFIE_HELLMAN;

    public static KeyExchangeAlgorithm getKeyExchangeAlgorithm(CipherSuite cipherSuite) {
	String cipher = cipherSuite.toString().toUpperCase();
	if (cipher.startsWith("TLS_RSA")) {
	    return RSA;
	} else if (cipher.startsWith("TLS_DH_DSS")) {
	    return DH_DSS;
	} else if (cipher.startsWith("TLS_DH_RSA")) {
	    return DH_RSA;
	} else if (cipher.startsWith("TLS_DHE_DSS")) {
	    return DHE_DSS;
	} else if (cipher.startsWith("TLS_DHE_RSA")) {
	    return DHE_RSA;
	} else if (cipher.startsWith("TLS_DH_ANON")) {
	    return DH_ANON;
	} else if (cipher.startsWith("TLS_ECDH")) {
	    return EC_DIFFIE_HELLMAN;
	}
	throw new UnsupportedOperationException("The key exchange algorithm is not supported yet.");
    }
}
