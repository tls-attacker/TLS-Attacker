/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.agent;

import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.result.Result;
import tlsattacker.fuzzer.server.ServerSerializer;
import tlsattacker.fuzzer.server.TLSServer;
import tlsattacker.fuzzer.testhelper.UnitTestCertificateMutator;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;
import tlsattacker.fuzzer.testvector.TestVector;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.Assert;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class PinAgentTest {

    /**
     *
     */
    private static PINAgent agent;

    /**
     *
     */
    private static TLSServer server;

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();
    
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
    public PinAgentTest() {
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
        agent = new PINAgent(config,pair);
        File f = new File("../resources/EvolutionaryFuzzer/TestServer/normal.config");
        if (!f.exists()) {
            Assert.fail("File does not exist:" + f.getAbsolutePath() + ", Configure the Fuzzer before building it!");
        }
        try {
            server = ServerSerializer.read(f);
            server.setConfig(config);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(AflAgentTest.class.getName()).log(Level.SEVERE, null, ex);
        }
        server.occupie();
    }

    /**
     *
     */
    @Test
    public void testStartStop() {
        agent.applicationStart(server);
        agent.applicationStop(server);
    }

    /**
     *
     */
    @Test(expected = IllegalStateException.class)
    public void testDoubleStart() {
        agent.applicationStart(server);
        agent.applicationStart(server);
    }

    /**
     *
     */
    @Test(expected = IllegalStateException.class)
    public void testNotStarted() {
        agent.applicationStop(server);
    }

    /**
     *
     */
    @Test(expected = IllegalStateException.class)
    public void testDoubleStop() {
        agent.applicationStart(server);
        agent.applicationStop(server);
        agent.applicationStop(server);

    }

    /**
     * Tests the Collect Results with a real world Demo Trace
     */
    @Test
    public void testCollectResults() {
        TestVector t = new TestVector(null, null, null, ExecutorType.TLS, null);
        agent.collectResults(new File("../resources/EvolutionaryFuzzer/PinTest/test.trace"), t);
    }

    /**
     * Tests if the collectResult methods constructs correct Graphs from the
     * trace files
     */
    @Test
    public void testCollectResultsGraph() {
        TestVector t = new TestVector(new WorkflowTrace(), null, null, ExecutorType.TLS, null);
        Result r = agent.collectResults(new File("../resources/EvolutionaryFuzzer/PinTest/graph.trace"), t);
        assertTrue("Failure: Test result should have exactly 4 Vertices",
                r.getBranchTrace().getVerticesSet().size() == 4);
        assertTrue("Failure: Test result should have exactly 6 Edges", r.getBranchTrace().getEdgeMap().size() == 6);

    }

    private static final Logger LOG = Logger.getLogger(PinAgentTest.class.getName());

}
