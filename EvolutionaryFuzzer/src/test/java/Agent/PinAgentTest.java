/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Agent;

import Agents.PINAgent;
import Config.ConfigManager;
import Config.EvolutionaryFuzzerConfig;
import Mutator.Certificate.FixedCertificateMutator;
import Result.Result;
import Server.ServerSerializer;
import Server.TLSServer;
import TestHelper.UnitTestCertificateMutator;
import Certificate.ServerCertificateStructure;
import TestVector.TestVector;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.util.FileHelper;
import java.io.File;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class PinAgentTest {

    private static PINAgent agent;
    private static TLSServer server;
    private UnitTestCertificateMutator mut = null;
    private ServerCertificateStructure pair = null;

    /**
     *
     */
    @AfterClass
    public static void tearDownClass() {
	File f = new File("JUNIT/");
	FileHelper.deleteFolder(f);

    }

    public PinAgentTest() {
    }

    @After
    public void tearDown() {
	FileHelper.deleteFolder(new File("unit_test_output"));
	FileHelper.deleteFolder(new File("unit_test_config"));
	ConfigManager.getInstance().setConfig(new EvolutionaryFuzzerConfig());
	server.stop();
	server = null;
    }

    @Before
    public void setUp() {
	EvolutionaryFuzzerConfig config = new EvolutionaryFuzzerConfig();
	config.setOutputFolder("unit_test_output/");
	config.setConfigFolder("unit_test_config/");
	ConfigManager.getInstance().setConfig(config);
	mut = new UnitTestCertificateMutator();
	pair = mut.getServerCertificateStructure();
	agent = new PINAgent(pair);
	File f = new File("../resources/EvolutionaryFuzzer/TestServer/normal.config");
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

    /**
     * Tests the Collect Results with a real world Demo Trace
     */
    @Test
    public void testCollectResults() {
	TestVector t = new TestVector(null, null, null, null);
	agent.collectResults(new File("../resources/EvolutionaryFuzzer/PinTest/test.trace"), t, t);
    }

    /**
     * Tests if the collectResult methods constructs correct Graphs from the
     * trace files
     */
    @Test
    public void testCollectResultsGraph() {
	TestVector t = new TestVector(new WorkflowTrace(), null, null, null);
	Result r = agent.collectResults(new File("../resources/EvolutionaryFuzzer/PinTest/graph.trace"), t, t);
	assertTrue("Failure: Test result should have exactly 4 Vertices",
		r.getBranchTrace().getVerticesSet().size() == 4);
	assertTrue("Failure: Test result should have exactly 6 Edges", r.getBranchTrace().getEdgeMap().size() == 6);

    }

}
