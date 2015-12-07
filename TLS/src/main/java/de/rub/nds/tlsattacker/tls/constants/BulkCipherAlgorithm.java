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

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public enum BulkCipherAlgorithm {

    /**
     * DESede references 3DES
     */
    NULL,
    DESede,
    RC4,
    AES;

    /**
     * @param cipherSuite
     * @return
     */
    public static BulkCipherAlgorithm getBulkCipherAlgorithm(CipherSuite cipherSuite) {
	String cipher = cipherSuite.toString().toUpperCase();
	if (cipher.contains("3DES_EDE")) {
	    return DESede;
	} else if (cipher.contains("AES")) {
	    return AES;
	} else if (cipher.contains("RC4")) {
	    return RC4;
	} else if (cipher.contains("NULL")) {
	    return NULL;
	}
	throw new UnsupportedOperationException("The cipher algorithm is not supported yet.");
    }

    public String getJavaName() {
	return this.toString();
    }
}
