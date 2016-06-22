/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package GlobalBranchTreeTests;

import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertFalse;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import tls.rub.evolutionaryfuzzer.TLSServer;

public class TLSServerTest
{

    private TLSServer server = null;

    /**
     *
     */
    public TLSServerTest()
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
        server = new TLSServer("127.0.0.1", 4433, "/home/ic0ns/Downloads/afl/afl-2.10b/afl-showmap -m none -o /home/ic0ns/Traces/openssl[id] /home/ic0ns/Downloads/afl/afl-2.10b/openssl-1.1.0-pre5/myOpenssl/bin/openssl s_server -naccept 1 -key /home/ic0ns/key.pem -cert /home/ic0ns/cert.pem -accept 4433", "ACCEPT");
    }

    /**
     *
     */
    @After
    public void tearDown()
    {
        server = null;
    }

    /**
     *
     */
    @Test
    public void testStart()
    {
        //TODO Test if really started
        server.occupie();
        server.start();
    }

    /**
     *
     */
    @Test
    public void testRestart()
    {
         //TODO Test if really started
        server.occupie();
        server.restart();
    }

    /**
     *
     */
    @Test
    public void testOccupie()
    {
         //TODO Test if really started
        server.occupie();
    }

    /**
     *
     */
    @Test
    public void testRelease()
    {
         //TODO Test if really started
        server.occupie();
        server.release();
    }

    /**
     *
     */
    @Test(expected = RuntimeException.class)
    public void testWrongOccupie()
    {
        server.occupie();
        server.occupie();
    }

    @Test(expected = RuntimeException.class)
    public void testWrongRelease()
    {
        server.release();
    }

    /**
     *
     */
    @Test(expected = RuntimeException.class)
    public void testExitedNotStarted()
    {
        server.exited();
    }

    /**
     *
     */
    @Test
    public void testExitedStarted()
    {
        server.occupie();
        server.start();
        assertFalse("Failure:Server started but should not have exited yet", server.exited());
    }
    private static final Logger LOG = Logger.getLogger(TLSServerTest.class.getName());
}
