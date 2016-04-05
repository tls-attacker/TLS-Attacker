/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security, Ruhr University
 * Bochum (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package de.rub.nds.tlsattacker.tls.constants;

import static de.rub.nds.tlsattacker.tls.constants.CipherAlgorithm.AES_128_CBC;
import static de.rub.nds.tlsattacker.tls.constants.CipherAlgorithm.AES_128_GCM;
import static de.rub.nds.tlsattacker.tls.constants.CipherAlgorithm.AES_256_CBC;
import static de.rub.nds.tlsattacker.tls.constants.CipherAlgorithm.AES_256_GCM;
import static de.rub.nds.tlsattacker.tls.constants.CipherAlgorithm.DES_EDE_CBC;
import static de.rub.nds.tlsattacker.tls.constants.CipherAlgorithm.NULL;
import static de.rub.nds.tlsattacker.tls.constants.CipherAlgorithm.RC4_128;
import static de.rub.nds.tlsattacker.tls.constants.CipherType.BLOCK;
import static de.rub.nds.tlsattacker.tls.constants.CipherType.STREAM;
import static de.rub.nds.tlsattacker.tls.constants.KeyExchangeAlgorithm.DHE_DSS;
import static de.rub.nds.tlsattacker.tls.constants.KeyExchangeAlgorithm.DHE_RSA;
import static de.rub.nds.tlsattacker.tls.constants.KeyExchangeAlgorithm.DH_ANON;
import static de.rub.nds.tlsattacker.tls.constants.KeyExchangeAlgorithm.DH_DSS;
import static de.rub.nds.tlsattacker.tls.constants.KeyExchangeAlgorithm.DH_RSA;
import static de.rub.nds.tlsattacker.tls.constants.KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN;
import static de.rub.nds.tlsattacker.tls.constants.KeyExchangeAlgorithm.RSA;
import static de.rub.nds.tlsattacker.tls.constants.MacAlgorithm.HMAC_MD5;
import static de.rub.nds.tlsattacker.tls.constants.MacAlgorithm.HMAC_SHA1;
import static de.rub.nds.tlsattacker.tls.constants.MacAlgorithm.HMAC_SHA256;
import static de.rub.nds.tlsattacker.tls.constants.MacAlgorithm.HMAC_SHA384;
import static de.rub.nds.tlsattacker.tls.constants.MacAlgorithm.HMAC_SHA512;
import static de.rub.nds.tlsattacker.tls.constants.MacAlgorithm.NULL;
import static de.rub.nds.tlsattacker.tls.constants.PRFAlgorithm.TLS_PRF_SHA256;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class AlgorithmResolver {

    private AlgorithmResolver() {

    }

    /**
     * Currently only this PRF is supported TODO: include support for further
     * types
     * 
     * @param protocolVersion
     * @param cipherSuite
     * @return
     */
    public static PRFAlgorithm getPRFAlgorithm(ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
	return TLS_PRF_SHA256;
    }

    /**
     * TODO handle aead ciphers
     * 
     * @param cipherSuite
     * @return
     */
    public static CipherAlgorithm getCipher(CipherSuite cipherSuite) {
	String cipher = cipherSuite.toString().toUpperCase();
	if (cipher.contains("NULL")) {
	    return CipherAlgorithm.NULL;
	} else if (cipher.contains("RC4")) {
	    return RC4_128;
	} else if (cipher.contains("DES_EDE_CBC")) {
	    return DES_EDE_CBC;
	} else if (cipher.contains("AES_128_CBC")) {
	    return AES_128_CBC;
	} else if (cipher.contains("AES_256_CBC")) {
	    return AES_256_CBC;
	} else if (cipher.contains("AES_128_GCM")) {
	    return AES_128_GCM;
	} else if (cipher.contains("AES_256_GCM")) {
	    return AES_256_GCM;
	}
	throw new UnsupportedOperationException("The cipher algorithm in " + cipherSuite + " is not supported yet.");
    }

    /**
     * @param cipherSuite
     * @return
     */
    public static MacAlgorithm getMacAlgorithm(CipherSuite cipherSuite) {
	String cipher = cipherSuite.toString();
	if (cipher.endsWith("MD5")) {
	    return HMAC_MD5;
	} else if (cipher.endsWith("SHA")) {
	    return HMAC_SHA1;
	} else if (cipher.endsWith("SHA256")) {
	    return HMAC_SHA256;
	} else if (cipher.endsWith("SHA384")) {
	    return HMAC_SHA384;
	} else if (cipher.endsWith("SHA512")) {
	    return HMAC_SHA512;
	} else if (cipher.endsWith("NULL")) {
	    return MacAlgorithm.NULL;
	}
	throw new UnsupportedOperationException("The Mac algorithm for cipher " + cipher + " is not supported yet");
    }

    /**
     * TODO handle aead ciphers
     * 
     * @param cipherSuite
     * @return
     */
    public static CipherType getCipherType(CipherSuite cipherSuite) {
	String cipher = cipherSuite.toString().toUpperCase();
	if (cipher.contains("AES") || cipher.contains("DES")) {
	    return BLOCK;
	} else if (cipher.contains("RC4")) {
	    return STREAM;
	}
	throw new UnsupportedOperationException("The cipher algorithm is not supported yet.");
    }

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
