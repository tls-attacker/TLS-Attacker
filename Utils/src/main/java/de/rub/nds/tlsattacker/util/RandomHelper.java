/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.util;

import java.util.Random;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class RandomHelper {

    private static Random random;

    private RandomHelper() {
    }

    public static Random getRandom() {
        if (random == null) {
            random = new Random();
        }
        return random;
    }
}
