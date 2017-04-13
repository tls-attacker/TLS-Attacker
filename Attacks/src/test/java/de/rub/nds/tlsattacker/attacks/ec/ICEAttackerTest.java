/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.ec;

import de.rub.nds.tlsattacker.attacks.ec.oracles.TestECOracle;
import de.rub.nds.tlsattacker.attacks.ec.oracles.TestECSunOracle;
import de.rub.nds.tlsattacker.tests.SlowTests;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.assertEquals;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class ICEAttackerTest {

    static Logger LOGGER = LogManager.getLogger(ICEAttackerTest.class);

    public ICEAttackerTest() {
    }

    /**
     * Test of attack method, of class ICEAttacker.
     */
    @Test()
    @Category(SlowTests.class)
    public void testAttack() {
        TestECOracle oracle = new TestECOracle("secp256r1");
        ICEAttacker attacker = new ICEAttacker(oracle);
        attacker.attack();
        BigInteger result = attacker.getResult();

        LOGGER.debug(result);
        LOGGER.debug(oracle.getComputer().getSecret());

        assertEquals(oracle.getComputer().getSecret(), result);
    }

    /**
     * Test of attack method, of class ICEAttacker.
     */
    @Ignore("This attack test would work only against an old vulnerable SUN implementation")
    @Test
    public void testSunAttack() {
        TestECSunOracle oracle = new TestECSunOracle("secp256r1");
        ICEAttacker attacker = new ICEAttacker(oracle, ICEAttacker.ServerType.ORACLE, 4);
        attacker.attack();
        BigInteger result = attacker.getResult();

        LOGGER.debug(result);
        LOGGER.debug(oracle.getComputer().getSecret());

        assertEquals(oracle.getComputer().getSecret(), result);
    }

}
