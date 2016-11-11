/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.agent;

import java.io.File;
import java.util.logging.Logger;
import org.junit.AfterClass;
import static org.junit.Assert.assertTrue;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class PINTest {

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

    /**
     *
     */
    public PINTest() {
    }

    /**
     *
     */
    @Test
    public void testPinExists() {
        File f = new File("PIN/pin");
        assertTrue("Failure: Could not find PIN implementation", f.exists());
        f = new File("PinScripts/MyPinTool.cpp");
        assertTrue("Failure: Could not find PIN script", f.exists());

    }

    private static final Logger LOG = Logger.getLogger(PINTest.class.getName());
}
