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

import de.rub.nds.tlsattacker.tls.crypto.ec.Curve;
import de.rub.nds.tlsattacker.tls.crypto.ec.Point;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public abstract class ECOracle {

    /**
     * logger
     */
    static Logger LOGGER = LogManager.getLogger(ECOracle.class);

    /*
     * number of queries issued to oracle
     */
    long numberOfQueries;

    /** curve used by the oracle */
    Curve curve;

    /**
     * Takes an ec point and a guessed secret and returns true, in case the
     * secret was guessed correctly.
     * 
     * @param ecPoint
     * @param guessedSecret
     * @return
     */
    public abstract boolean checkSecretCorrectnes(Point ecPoint, BigInteger guessedSecret);

    /**
     * Sends the oracle a request with a guessed secret key resulting from the
     * attack. The oracle responds with true, in case the guessed key was
     * correct.
     * 
     * @param guessedSecret
     * @return
     */
    public abstract boolean isFinalSolutionCorrect(BigInteger guessedSecret);

    public long getNumberOfQueries() {
	return numberOfQueries;
    }

    public void setNumberOfQueries(long numberOfQueries) {
	this.numberOfQueries = numberOfQueries;
    }

    public Curve getCurve() {
	return curve;
    }

    public void setCurve(Curve curve) {
	this.curve = curve;
    }
}
