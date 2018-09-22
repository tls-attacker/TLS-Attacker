/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.ec.oracles;

import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.DivisionException;
import de.rub.nds.tlsattacker.core.crypto.ec.ECComputer;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import java.math.BigInteger;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author robert
 */
public class TestECOracle extends ECOracle {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ECComputer computer;

    /**
     *
     * @param namedCurve
     */
    public TestECOracle(String namedCurve) {
        curve = CurveFactory.getNamedCurve(namedCurve);
        BigInteger privateKey = new BigInteger(curve.getKeyBits(), new Random());
        computer = new ECComputer(curve, privateKey);
    }

    @Override
    public boolean checkSecretCorrectnes(Point ecPoint, BigInteger guessedSecret) {
        numberOfQueries++;
        if (numberOfQueries % 100 == 0) {
            LOGGER.debug("Number of queries so far: {}", numberOfQueries);
        }
        Point result;
        try {
            result = computer.mul(ecPoint, true);
        } catch (DivisionException ex) {
            result = null;
        }

        if (result == null || result.isInfinity()) {
            return false;
        } else {
            return (result.getX().compareTo(guessedSecret) == 0);
        }
    }

    /**
     *
     * @return
     */
    public ECComputer getComputer() {
        return computer;
    }

    @Override
    public boolean isFinalSolutionCorrect(BigInteger guessedSecret) {
        return guessedSecret.equals(computer.getSecret());
    }
}
