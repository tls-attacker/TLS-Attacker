/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.tokenbinding;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;


public class TokenCalculator {

    private TokenCalculator() {
    }

    public static byte[] calculateEKM(Chooser chooser, int length) {
        byte[] masterSecret = chooser.getMasterSecret();
        String label = TokenBindingLabel.TOKEN_LABEL;
        byte[] clientServerRandom = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        PRFAlgorithm algorithm = AlgorithmResolver.getPRFAlgorithm(chooser.getSelectedProtocolVersion(),
                chooser.getSelectedCipherSuite());
        return PseudoRandomFunction.compute(algorithm, masterSecret, label, clientServerRandom, length);
    }

}
