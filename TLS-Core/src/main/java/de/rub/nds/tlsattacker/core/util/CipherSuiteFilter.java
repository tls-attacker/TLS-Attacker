/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import java.util.List;

public class CipherSuiteFilter {

    /**
     * CipherSuite filtering based on the key exchange method and on the
     * ephemeral property. This method is useful for establishing new workflows.
     * 
     * @param cipherSuites
     *            The CipherSuites that should be filtered
     */
    public static void filterCipherSuites(List<CipherSuite> cipherSuites) {
        KeyExchangeAlgorithm algorithm = AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuites.get(0));
        boolean ephemeral = cipherSuites.get(0).isEphemeral();
        for (int i = cipherSuites.size() - 1; i > 0; i--) {
            CipherSuite cs = cipherSuites.get(i);
            if (AlgorithmResolver.getKeyExchangeAlgorithm(cs) != algorithm || cs.isEphemeral() != ephemeral) {
                cipherSuites.remove(i);
            }
        }
    }

    private CipherSuiteFilter() {
    }
}
