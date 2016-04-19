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
package de.rub.nds.tlsattacker.tls.constants;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Resolves crypto algorithms and their properties from a given cipehr suite
 * (and TLS version).
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class AlgorithmResolver {

    private static final Logger LOGGER = LogManager.getLogger(AlgorithmResolver.class);

    private AlgorithmResolver() {

    }

    /**
     * Returns a PRF algorithm based on the protocol version and the cipher
     * suite. TLS 1.0 and 1.1 used a legacy PRF based on MD5 and SHA-1. TLS 1.2
     * uses per default SHA256 PRF, but allows for definition of further PRFs in
     * specific cipher suites (the last part of a cipher suite string identifies
     * the PRF).
     * 
     * @param protocolVersion
     * @param cipherSuite
     * @return
     */
    public static PRFAlgorithm getPRFAlgorithm(ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
	PRFAlgorithm result;
	if (protocolVersion == ProtocolVersion.TLS10 || protocolVersion == ProtocolVersion.TLS11
		|| protocolVersion == ProtocolVersion.DTLS10) {
	    result = PRFAlgorithm.TLS_PRF_LEGACY;
	} else if (cipherSuite.name().endsWith("SHA384")) {
	    result = PRFAlgorithm.TLS_PRF_SHA384;
	} else {
	    result = PRFAlgorithm.TLS_PRF_SHA256;
	}
	LOGGER.debug("Using the following PRF Algorithm: {}", result);
	return result;
    }

    /**
     * Returns a digest algorithm based on the protocol version and the cipher
     * suite. The digest algorithm is used to compute a message digest over the
     * handshake messages and to compute valid finished messages. TLS 1.0 and
     * 1.1 used a legacy digest based on MD5 and SHA-1. TLS 1.2 uses per default
     * SHA256 digest algorithm, but allows for definition of further digest
     * algorithms in specific cipher suites (the last part of a cipher suite
     * string identifies the digest).
     * 
     * @param protocolVersion
     * @param cipherSuite
     * @return
     */
    public static DigestAlgorithm getDigestAlgorithm(ProtocolVersion protocolVersion, CipherSuite cipherSuite) {
	DigestAlgorithm result;
	if (protocolVersion == ProtocolVersion.TLS10 || protocolVersion == ProtocolVersion.TLS11
		|| protocolVersion == ProtocolVersion.DTLS10) {
	    result = DigestAlgorithm.LEGACY;
	} else if (cipherSuite.name().endsWith("SHA384")) {
	    result = DigestAlgorithm.SHA384;
	} else {
	    result = DigestAlgorithm.SHA256;
	}
	LOGGER.debug("Using the following Digest Algorithm: {}", result);
	return result;
    }

    public static KeyExchangeAlgorithm getKeyExchangeAlgorithm(CipherSuite cipherSuite) {
	String cipher = cipherSuite.toString().toUpperCase();
	if (cipher.startsWith("TLS_RSA")) {
	    return KeyExchangeAlgorithm.RSA;
	} else if (cipher.startsWith("TLS_DH_DSS")) {
	    return KeyExchangeAlgorithm.DH_DSS;
	} else if (cipher.startsWith("TLS_DH_RSA")) {
	    return KeyExchangeAlgorithm.DH_RSA;
	} else if (cipher.startsWith("TLS_DHE_DSS")) {
	    return KeyExchangeAlgorithm.DHE_DSS;
	} else if (cipher.startsWith("TLS_DHE_RSA")) {
	    return KeyExchangeAlgorithm.DHE_RSA;
	} else if (cipher.startsWith("TLS_DH_ANON")) {
	    return KeyExchangeAlgorithm.DH_ANON;
	} else if (cipher.startsWith("TLS_ECDH")) {
	    return KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN;
	}
	throw new UnsupportedOperationException("The key exchange algorithm is not supported yet.");
    }

    public static CipherAlgorithm getCipher(CipherSuite cipherSuite) {
	String cipher = cipherSuite.toString().toUpperCase();
	if (cipher.contains("NULL")) {
	    return CipherAlgorithm.NULL;
	} else if (cipher.contains("RC4")) {
	    return CipherAlgorithm.RC4_128;
	} else if (cipher.contains("DES_EDE_CBC")) {
	    return CipherAlgorithm.DES_EDE_CBC;
	} else if (cipher.contains("AES_128_CBC")) {
	    return CipherAlgorithm.AES_128_CBC;
	} else if (cipher.contains("AES_256_CBC")) {
	    return CipherAlgorithm.AES_256_CBC;
	} else if (cipher.contains("AES_128_GCM")) {
	    return CipherAlgorithm.AES_128_GCM;
	} else if (cipher.contains("AES_256_GCM")) {
	    return CipherAlgorithm.AES_256_GCM;
	}
	throw new UnsupportedOperationException("The cipher algorithm in " + cipherSuite + " is not supported yet.");
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
	    return CipherType.BLOCK;
	} else if (cipher.contains("RC4")) {
	    return CipherType.STREAM;
	}
	throw new UnsupportedOperationException("The cipher algorithm is not supported yet.");
    }

    public static MacAlgorithm getMacAlgorithm(CipherSuite cipherSuite) {
	MacAlgorithm result = null;
	if (cipherSuite.isAEAD()) {
	    result = MacAlgorithm.AEAD;
	} else {
	    String cipher = cipherSuite.toString();
	    if (cipher.endsWith("MD5")) {
		result = MacAlgorithm.HMAC_MD5;
	    } else if (cipher.endsWith("SHA")) {
		result = MacAlgorithm.HMAC_SHA1;
	    } else if (cipher.endsWith("SHA256")) {
		result = MacAlgorithm.HMAC_SHA256;
	    } else if (cipher.endsWith("SHA384")) {
		result = MacAlgorithm.HMAC_SHA384;
	    } else if (cipher.endsWith("SHA512")) {
		result = MacAlgorithm.HMAC_SHA512;
	    } else if (cipher.endsWith("NULL")) {
		result = MacAlgorithm.NULL;
	    }
	}
	if (result != null) {
	    LOGGER.debug("Using the following Mac Algorithm: {}", result);
	    return result;
	} else {
	    throw new UnsupportedOperationException("The Mac algorithm for cipher " + cipherSuite
		    + " is not supported yet");
	}
    }
}
