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
import org.junit.Before;
import org.junit.Test;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.server.ServerSerializer;
import tlsattacker.fuzzer.server.TLSServer;
import tlsattacker.fuzzer.mutator.certificate.UnitTestCertificateMutator;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;
import tlsattacker.fuzzer.result.AgentResult;
import tlsattacker.fuzzer.testvector.TestVector;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.After;
import org.junit.Assert;
import static org.junit.Assert.assertTrue;
import org.junit.Rule;
import org.junit.experimental.categories.Category;
import org.junit.rules.TemporaryFolder;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AflAgentTest {

    private static final Logger LOGGER = LogManager.getLogger(AflAgentTest.class);

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    /**
     *
     */
    private AFLAgent agent = null;

    /**
     *
     */
    private TLSServer server = null;

    /**
     *
     */
    private UnitTestCertificateMutator mut = null;

    /**
     *
     */
    private ServerCertificateStructure pair = null;

    /**
     *
     */
    public AflAgentTest() {
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
    @Before
    public void setUp() throws IOException {
        EvolutionaryFuzzerConfig config = new EvolutionaryFuzzerConfig();
        config.setOutputFolder(tempFolder.newFolder().getAbsolutePath());
        config.setConfigFolder(tempFolder.newFolder().getAbsolutePath());
        config.createFolders();
        mut = new UnitTestCertificateMutator();
        pair = mut.getServerCertificateStructure();
        File f = new File("../resources/EvolutionaryFuzzer/TestServer/afl.config");
        if (!f.exists()) {
            Assert.fail("File does not exist:" + f.getAbsolutePath() + ", Configure the Fuzzer before building it!");
        }
        try {
            server = ServerSerializer.read(f);
            server.setConfig(config);
        } catch (Exception ex) {
            LOGGER.error(ex.getLocalizedMessage(), ex);
        }
        agent = new AFLAgent(pair, server);
        server.occupie();

    }

    /**
     *
     */
    @Test
    @Category(IntegrationTest.class)
    public void testStartStop() {
        agent.applicationStart();
        agent.applicationStop();
    }

    /**
     *
     */
    @Test(expected = IllegalStateException.class)
    @Category(IntegrationTest.class)
    public void testDoubleStart() {
        agent.applicationStart();
        agent.applicationStart();
    }

    /**
     *
     */
    @Test(expected = IllegalStateException.class)
    @Category(IntegrationTest.class)
    public void testNotStarted() {
        agent.applicationStop();
    }

    /**
     *
     */
    @Test(expected = IllegalStateException.class)
    @Category(IntegrationTest.class)
    public void testDoubleStop() {
        agent.applicationStart();
        agent.applicationStop();
        agent.applicationStop();
    }

    // /**
    // *
    // */
    // @Test
    // @Category(IntegrationTest.class)
    // public void testCollectResults() {
    // TestVector t = new TestVector(new WorkflowTrace(), null, null,
    // ExecutorType.TLS, null);
    // AgentResult r = agent.collectResults(new
    // File("../resources/EvolutionaryFuzzer/AFLTest/graph.trace"), t);
    // assertTrue("Failure: Test result should have exactly 4 Vertices",
    // r.getInstrumentationMap().getVerticesSet().size() == 4);
    // assertTrue("Failure: Test result should have exactly 6 Edges",
    // r.getInstrumentationMap().getEdgeMap().size() == 6);
    // }

}
