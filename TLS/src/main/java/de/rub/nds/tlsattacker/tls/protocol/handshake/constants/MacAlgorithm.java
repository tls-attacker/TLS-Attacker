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
public enum MacAlgorithm {

    NULL("null"),
    HMAC_MD5("HmacMD5"),
    HMAC_SHA1("HmacSHA1"),
    HMAC_SHA256("HmacSHA256"),
    HMAC_SHA384("HmacSHA384"),
    HMAC_SHA512("HmacSHA512");

    MacAlgorithm(String javaName) {
	this.javaName = javaName;
    }

    private String javaName;

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
	    return NULL;
	}
	throw new UnsupportedOperationException("The Mac algorithm for cipher " + cipher + " is not supported yet");
    }

    public String getJavaName() {
	return javaName;
    }
}
