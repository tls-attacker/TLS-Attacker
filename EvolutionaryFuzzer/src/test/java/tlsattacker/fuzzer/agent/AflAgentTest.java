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
import org.junit.Before;
import org.junit.Test;
import tlsattacker.fuzzer.agents.AFLAgent;
import tlsattacker.fuzzer.config.ConfigManager;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.server.ServerSerializer;
import tlsattacker.fuzzer.server.TLSServer;
import tlsattacker.fuzzer.testhelper.UnitTestCertificateMutator;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;
import tlsattacker.fuzzer.result.Result;
import tlsattacker.fuzzer.testvector.TestVector;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import de.rub.nds.tlsattacker.util.FileHelper;
import java.util.logging.Level;
import org.junit.After;
import org.junit.Assert;
import static org.junit.Assert.assertTrue;

/**
 * 
 * @author ic0ns
 */
public class AflAgentTest {
    private static final Logger LOG = Logger.getLogger(AflAgentTest.class.getName());

    /**
     *
     */
    @AfterClass
    public static void tearDownClass() {
        
        File f = new File("JUNIT/");
        FileHelper.deleteFolder(f);
        
    }


    private AFLAgent agent = null;
    private TLSServer server = null;
    private UnitTestCertificateMutator mut = null;
    private ServerCertificateStructure pair = null;

    /**
     *
     */
    public AflAgentTest() {
    }

    @After
    public void tearDown() {
        FileHelper.deleteFolder(new File("unit_test_output"));
        FileHelper.deleteFolder(new File("unit_test_config"));
        ConfigManager.getInstance().setConfig(new EvolutionaryFuzzerConfig());
        server.stop();
	server = null;
    }
    
    /**
     *
     */
    @Before
    public void setUp() {
        EvolutionaryFuzzerConfig config = new EvolutionaryFuzzerConfig();
        config.setOutputFolder("unit_test_output/");
        config.setConfigFolder("unit_test_config/");
        ConfigManager.getInstance().setConfig(config);
        mut = new UnitTestCertificateMutator();
        pair = mut.getServerCertificateStructure();
        agent = new AFLAgent(pair);
        File f = new File("../resources/EvolutionaryFuzzer/TestServer/afl.config");
        if (!f.exists()) {
            Assert.fail("File does not exist:" + f.getAbsolutePath() + ", Configure the Fuzzer before building it!");
        }
        try {
            server = ServerSerializer.read(f);
        } catch (Exception ex) {
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

    @Test
    public void testCollectResults()
    {
        TestVector t = new TestVector(new WorkflowTrace(), null, null, ExecutorType.TLS, null);
        Result r = agent.collectResults(new File("../resources/EvolutionaryFuzzer/AFLTest/graph.trace"), t);
        assertTrue("Failure: Test result should have exactly 4 Vertices",
		r.getBranchTrace().getVerticesSet().size() == 4);
	assertTrue("Failure: Test result should have exactly 6 Edges", r.getBranchTrace().getEdgeMap().size() == 6);
    }

}
