/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.config;

import java.util.logging.Logger;
import org.junit.AfterClass;
import static org.junit.Assert.assertNotNull;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ConfigManagerTest {

    /**
     *
     */
    @BeforeClass
    public static void setUpClass() {
    }

    /**
     *
     */
    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() throws Exception {
    }

    /**
     *
     */
    public ConfigManagerTest() {
    }

    /**
     *
     */
    @Test
    public void testSingleTon() {
        ConfigManager.getInstance();
    }

    /**
     *
     */
    @Test
    public void testGetConfig() {
        assertNotNull("Failure: Could get a ConfigManager Instance", ConfigManager.getInstance().getConfig());
    }

    private static final Logger LOG = Logger.getLogger(ConfigManagerTest.class.getName());

    /**
     * Test of getInstance method, of class ConfigManager.
     */
    @Test
    public void testGetInstance() {
    }

    /**
     * Test of setConfig method, of class ConfigManager.
     */
    @Test
    public void testSetConfig() {
    }

}
