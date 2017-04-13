/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable.bool;

import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.util.RandomHelper;
import java.math.BigInteger;
import java.util.Random;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class BooleanModificationFactory {

    private static final int MODIFICATION_COUNT = 3;

    public static VariableModification<Boolean> createRandomModification() {
        Random random = RandomHelper.getRandom();
        switch (random.nextInt(MODIFICATION_COUNT)) {
            case 0:
                return new BooleanExplicitValueModification(true);
            case 1:
                return new BooleanExplicitValueModification(false);
            case 2:
                return new BooleanToogleModification();
        }
        return null;
    }
}
