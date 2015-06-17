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
