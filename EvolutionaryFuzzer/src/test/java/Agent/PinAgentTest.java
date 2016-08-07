/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Agent;

import static Agent.AflAgentTest.deleteFolder;
import Agents.PINAgent;
import Mutator.Certificate.FixedCertificateMutator;
import Result.Result;
import Server.ServerSerializer;
import Server.TLSServer;
import TestVector.ServerCertificateKeypair;
import TestVector.TestVector;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
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
    private FixedCertificateMutator mut = null;
    private ServerCertificateKeypair pair = null;

    /**
     *
     */
    @AfterClass
    public static void tearDownClass() {
	File f = new File("JUNIT/");
	deleteFolder(f);

    }

    public PinAgentTest() {
    }

    @Before
    public void setUp() {
	mut = new FixedCertificateMutator();
	pair = mut.getServerCertificateKeypair();
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

    @After
    public void tearDown() {
	server.stop();
	server = null;
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
	TestVector t = new TestVector(null, null, null);
	agent.collectResults(new File("../resources/EvolutionaryFuzzer/PinTest/test.trace"), t, t);
    }

    /**
     * Tests if the collectResult methods constructs correct Graphs from the
     * trace files
     */
    @Test
    public void testCollectResultsGraph() {
	TestVector t = new TestVector(new WorkflowTrace(), null, null);
	Result r = agent.collectResults(new File("../resources/EvolutionaryFuzzer/PinTest/graph.trace"), t, t);
	assertTrue("Failure: Test result should have exactly 4 Vertices",
		r.getBranchTrace().getVerticesSet().size() == 4);
	assertTrue("Failure: Test result should have exactly 6 Edges", r.getBranchTrace().getEdgeMap().size() == 6);

    }

}
