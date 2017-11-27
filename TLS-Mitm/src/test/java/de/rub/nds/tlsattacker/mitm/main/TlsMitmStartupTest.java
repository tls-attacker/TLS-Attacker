/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.mitm.main;

import static de.rub.nds.tlsattacker.util.FileHelper.getResourceAsString;
import de.rub.nds.tlsattacker.util.tests.IntegrationTests;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Verify that the startup procedure works. This test simply simulates command
 * line execution of the TLS-Mitm module and checks against expected debug
 * output.
 * 
 * Note: This test is rather strict. If adding similar tests, consider to
 * compare based on Level.INFO.
 * 
 * TODO: This is certainly an intermediate solution only. Feel free to remove
 * this test once the testing environment is setup :)
 */
public class TlsMitmStartupTest {

    protected static final Logger LOGGER = LogManager.getLogger(TlsMitmStartupTest.class.getName());

    // Grant enough time, 1000 should be enough even for slow systems
    private final int timeout = 1000;

    @Before
    public void setUp() {
        Configurator.setRootLevel(Level.INFO);
    }

    @Category(IntegrationTests.class)
    @Test
    public void startupTest() {
        String expected = getResourceAsString(this.getClass(), "/mitm_startup.txt");
        String[] params = { "-accept", "19721", "-connect", "localhost:16710", "-debug" };

        ExecutionRecorder recorder = new ExecutionRecorder(params, expected, timeout, Level.DEBUG);
        recorder.run();

        assertEquals(recorder.getRecordedOutput(), expected);
    }
}
