/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.agent;

import de.rub.nds.tlsattacker.tests.IntegrationTest;
import java.io.File;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.experimental.categories.Category;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AFLTest {

    /**
     *
     */
    private static final Logger LOG = Logger.getLogger(AFLTest.class.getName());

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
    public AFLTest() {
    }

    /**
     *
     */
    @Before
    public void setUp() {
    }

    /**
     *
     */
    @After
    public void tearDown() {
    }

    /**
     *
     */
    @Category(IntegrationTest.class)
    public void testAflexists() {
        File f = new File("AFL/afl-as");
        assertTrue("Failure: Tool afl-as was not found", f.exists());
        f = new File("AFL/afl-showmap");
        assertTrue("Failure: Tool afl-showmap was not found", f.exists());

    }

}
