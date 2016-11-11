/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
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
