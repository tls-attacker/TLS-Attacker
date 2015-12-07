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
package de.rub.nds.tlsattacker.tls.config;

import de.rub.nds.tlsattacker.tls.constants.CipherSuite;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public enum ServerCertificateKey {

    EC,
    DH,
    RSA,
    NONE;

    public static ServerCertificateKey getServerCertificateKey(CipherSuite cipherSuite) {
	String cipher = cipherSuite.toString().toUpperCase();
	if (cipher.startsWith("TLS_RSA") || cipher.matches("^TLS_[A-Z]+_RSA.+")) {
	    return RSA;
	} else if (cipher.matches("^TLS_[A-Z]+_DSS.+")) {
	    return DH;
	} else if (cipher.matches("^TLS_[A-Z]+_ECDSA.+")) {
	    return EC;
	} else {
	    return NONE;
	}
    }
}
