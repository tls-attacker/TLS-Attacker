/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.ec;

import de.rub.nds.tlsattacker.attacks.ec.oracles.TestECOracle;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import de.rub.nds.tlsattacker.util.tests.SlowTests;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 *
 *
 */
public class ICEAttackerTest {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     *
     */
    public ICEAttackerTest() {
    }

    /**
     * Test of attack method, of class ICEAttacker.
     */
    @Test()
    @Category(SlowTests.class)
    public void testAttack() {
        CONSOLE.info("Starting ICEAttacker test... this may take some time");
        TestECOracle oracle = new TestECOracle(NamedGroup.SECP256R1);
        ICEAttacker attacker = new ICEAttacker(oracle, ICEAttacker.ServerType.ORACLE, 4, NamedGroup.SECP256R1);
        BigInteger result = attacker.attack();

        LOGGER.debug(result);
        LOGGER.debug(oracle.getPrivateKey());

        assertEquals(oracle.getPrivateKey(), result);
    }
}
