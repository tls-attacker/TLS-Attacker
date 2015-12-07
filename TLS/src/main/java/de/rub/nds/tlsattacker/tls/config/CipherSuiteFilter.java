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
package de.rub.nds.tlsattacker.tls.config;

import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.KeyExchangeAlgorithm;
import java.util.List;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class CipherSuiteFilter {

    /**
     * CipherSuite filtering based on the key exchange method and on the
     * ephemeral property. This method is useful for establishing new workflows.
     * 
     * @param cipherSuites
     */
    public static void filterCipherSuites(List<CipherSuite> cipherSuites) {
	KeyExchangeAlgorithm algorithm = KeyExchangeAlgorithm.getKeyExchangeAlgorithm(cipherSuites.get(0));
	boolean ephemeral = cipherSuites.get(0).isEphemeral();
	for (int i = cipherSuites.size() - 1; i > 0; i--) {
	    CipherSuite cs = cipherSuites.get(i);
	    if (KeyExchangeAlgorithm.getKeyExchangeAlgorithm(cs) != algorithm || cs.isEphemeral() != ephemeral) {
		cipherSuites.remove(i);
	    }
	}
    }
}
