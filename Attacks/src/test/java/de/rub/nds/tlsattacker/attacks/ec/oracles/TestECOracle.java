package de.rub.nds.tlsattacker.attacks.ec.oracles;

import de.rub.nds.tlsattacker.attacks.ec.oracles.ECOracle;
import de.rub.nds.tlsattacker.tls.crypto.ec.Curve;
import de.rub.nds.tlsattacker.tls.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.tls.crypto.ec.DivisionException;
import de.rub.nds.tlsattacker.tls.crypto.ec.ECComputer;
import de.rub.nds.tlsattacker.tls.crypto.ec.Point;
import java.math.BigInteger;
import java.util.Random;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class TestECOracle extends ECOracle {

    private final ECComputer computer;

    public TestECOracle(String namedCurve) {
	curve = CurveFactory.getNamedCurve(namedCurve);
	BigInteger privateKey = new BigInteger(curve.getKeyBits(), new Random());
	computer = new ECComputer(curve, privateKey);
    }

    @Override
    public boolean checkSecretCorrectnes(Point ecPoint, BigInteger guessedSecret) {
	numberOfQueries++;
	if (numberOfQueries % 100 == 0) {
	    LOGGER.info("Number of queries so far: {}", numberOfQueries);
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

    public ECComputer getComputer() {
	return computer;
    }

    @Override
    public boolean isFinalSolutionCorrect(BigInteger guessedSecret) {
	if (guessedSecret.equals(computer.getSecret())) {
	    return true;
	} else {
	    return false;
	}
    }
}
