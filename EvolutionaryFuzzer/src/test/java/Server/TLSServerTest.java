package Server;

import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import Server.TLSServer;

/**
 * 
 * @author ic0ns
 */
public class TLSServerTest {
    private static final Logger LOG = Logger.getLogger(TLSServerTest.class.getName());

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

    private TLSServer server = null;

    /**
     *
     */
    public TLSServerTest() {
    }

    /**
     *
     */
    @Before
    public void setUp() {
	server = new TLSServer(
		"127.0.0.1",
		4433,
		"/home/ic0ns/Downloads/afl/afl-2.10b/afl-showmap -m none -o /home/ic0ns/Traces/openssl[id] /home/ic0ns/Downloads/afl/afl-2.10b/openssl-1.1.0-pre5/myOpenssl/bin/openssl s_server -naccept 1 -key /home/ic0ns/key.pem -cert /home/ic0ns/cert.pem -accept 4433",
		"ACCEPT", "./");
    }

    /**
     *
     */
    @After
    public void tearDown() {
	server = null;
    }

    /**
     *
     */
    @Test
    public void testStart() {
	// TODO Test if really started
	// TODO
	server.occupie();
	server.start("AFL/afl-showmap -m none -o [output]/[id] ");

    }

    /**
     *
     */
    @Test
    public void testRestart() {
	// TODO Test if really started
	server.occupie();
	server.restart("AFL/afl-showmap -m none -o [output]/[id] ");
    }

    /**
     *
     */
    @Test
    public void testOccupie() {
	server.occupie();
	assertFalse(server.isFree());
    }

    /**
     *
     */
    @Test
    public void testRelease() {

	server.occupie();
	server.release();
	assertTrue(server.isFree());
    }

    /**
     *
     */
    @Test(expected = IllegalStateException.class)
    public void testWrongOccupie() {
	server.occupie();
	server.occupie();
    }

    @Test(expected = IllegalStateException.class)
    public void testWrongRelease() {
	server.release();
    }

    /**
     *
     */
    @Test(expected = IllegalStateException.class)
    public void testExitedNotStarted() {
	server.exited();
    }

    /**
     *
     */
    @Test
    public void testExitedStarted() {
	server.occupie();
	server.start("AFL/afl-showmap -m none -o [output]/[id] ");
	assertFalse("Failure: Server started but should not have exited yet", server.exited());
    }

}
