/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Agent;

import static Agent.AflAgentTest.deleteFolder;
import Agents.AFLAgent;
import Agents.PINAgent;
import Result.Result;
import Server.ServerManager;
import Server.TLSServer;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.io.File;
import org.junit.AfterClass;
import org.junit.BeforeClass;
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

    /**
     *
     */
    @AfterClass
    public static void tearDownClass() {
	File f = new File("JUNIT");
	deleteFolder(f);

    }

    public PinAgentTest() {
    }

    @Before
    public void setUp() {
	agent = new PINAgent();
	server = new TLSServer(
		"127.0.0.1",
		4433,
		"openssl/openssl/bin/openssl s_server -naccept 1 -key /home/ic0ns/key.pem -cert /home/ic0ns/cert.pem -accept [port]",
		"ACCEPT", "JUNIT/");
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
	WorkflowTrace t = new WorkflowTrace();
	agent.collectResults(new File("../resources/testsuite/EvolutionaryFuzzer/PinTest/test.trace"), t, t);
    }

    /**
     * Tests if the collectResult methods constructs correct Graphs from the
     * trace files
     */
    @Test
    public void testCollectResultsGraph() {
	WorkflowTrace t = new WorkflowTrace();
	Result r = agent
		.collectResults(new File("../resources/testsuite/EvolutionaryFuzzer/PinTest/graph.trace"), t, t);
	assertTrue("Failure: Test result should have exactly 4 Vertices", r.getBranchTrace().getGraph().vertexSet().size() == 4);
	assertTrue("Failure: Test result should have exactly 6 Edges", r.getBranchTrace().getGraph().edgeSet().size() == 6);

    }

}
