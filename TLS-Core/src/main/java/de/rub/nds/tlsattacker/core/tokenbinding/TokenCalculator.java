/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.tokenbinding;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class TokenCalculator {

    private TokenCalculator() {
    }

    public static byte[] calculateEKM(TlsContext context, int length) {
        byte[] masterSecret = context.getMasterSecret();
        String label = TokenBindingLabel.TOKEN_LABEL;
        byte[] clientServerRandom = context.getClientServerRandom();
        PRFAlgorithm algorithm = AlgorithmResolver.getPRFAlgorithm(context.getSelectedProtocolVersion(),
                context.getSelectedCipherSuite());
        return PseudoRandomFunction.compute(algorithm, masterSecret, label, clientServerRandom, length);
    }

}
