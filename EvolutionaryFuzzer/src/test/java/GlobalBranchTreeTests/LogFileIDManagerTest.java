/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package GlobalBranchTreeTests;

import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import tls.rub.evolutionaryfuzzer.LogFileIDManager;


public class LogFileIDManagerTest
{

    /**
     *
     */
    public LogFileIDManagerTest()
    {
    }

    /**
     *
     */
    @BeforeClass
    public static void setUpClass()
    {
    }

    /**
     *
     */
    @AfterClass
    public static void tearDownClass()
    {
    }

    /**
     *
     */
    @Before
    public void setUp()
    {
    }

    /**
     *
     */
    @After
    public void tearDown()
    {
    }

    /**
     *
     */
    @Test
    public void testIncrementingIDs()
    {
        
        assertTrue("Failure: Incrementing the LogFileIDs failed",LogFileIDManager.getInstance().getID()==LogFileIDManager.getInstance().getID()-1);
    }
    private static final Logger LOG = Logger.getLogger(LogFileIDManagerTest.class.getName());
}
