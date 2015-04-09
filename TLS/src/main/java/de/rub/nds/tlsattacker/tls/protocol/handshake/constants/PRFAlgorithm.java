/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
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

import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public enum PRFAlgorithm {

    TLS_PRF_SHA256("HmacSHA256");

    private PRFAlgorithm(String javaName) {
	this.javaName = javaName;
    }

    private String javaName;

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

    public String getJavaName() {
	return javaName;
    }
}
