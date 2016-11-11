package tlsattacker.fuzzer.server;

import java.io.File;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import tlsattacker.fuzzer.agent.AflAgentTest;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;
import tlsattacker.fuzzer.mutator.certificate.CertificateMutator;
import tlsattacker.fuzzer.testhelper.UnitTestCertificateMutator;

/**
 * 
 * @author ic0ns
 */
public class TLSServerTest {

    /**
     *
     */
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

    /**
     *
     */
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
        File f = new File("../resources/EvolutionaryFuzzer/TestServer/server.config");
        if (!f.exists()) {
            Assert.fail("File does not exist:" + f.getAbsolutePath() + ", Configure the Fuzzer before building it!");
        }
        try {
            server = ServerSerializer.read(f);
        } catch (Exception ex) {
            Logger.getLogger(AflAgentTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     *
     */
    @After
    public void tearDown() {
        server.stop();
        server = null;
    }

    /**
     *
     */
    @Test
    public void testStart() {
        server.occupie();
        CertificateMutator mut = new UnitTestCertificateMutator();
        ServerCertificateStructure cert = mut.getServerCertificateStructure();
        server.start("", cert.getCertificateFile(), cert.getKeyFile());
        server.serverHasBooted();
    }

    /**
     *
     */
    @Test
    public void testRestart() {
        server.occupie();
        CertificateMutator mut = new UnitTestCertificateMutator();
        ServerCertificateStructure cert = mut.getServerCertificateStructure();
        server.start("", cert.getCertificateFile(), cert.getKeyFile());
        server.serverHasBooted();
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

    /**
     *
     */
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
        CertificateMutator mut = new UnitTestCertificateMutator();
        ServerCertificateStructure cert = mut.getServerCertificateStructure();
        server.start("", cert.getCertificateFile(), cert.getKeyFile());
        assertFalse("Failure: Server started but should not have exited yet", server.exited());
    }
    // TODO Test if a started server accepts a tls connection
}
