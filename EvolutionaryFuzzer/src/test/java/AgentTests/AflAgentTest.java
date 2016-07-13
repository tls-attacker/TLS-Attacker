/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package AgentTests;

import java.io.File;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import Agents.AFLAgent;
import Server.ServerManager;
import Server.TLSServer;

/**
 * 
 * @author ic0ns
 */
public class AflAgentTest {

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
	File f = new File("JUNIT");
	deleteFolder(f);

    }

    AFLAgent agent = null;
    TLSServer server = null;

    public static void deleteFolder(File folder) {
	File[] files = folder.listFiles();
	if (files != null) { // some JVMs return null for empty dirs
	    for (File f : files) {
		if (f.isDirectory()) {
		    deleteFolder(f);
		} else {
		    f.delete();
		}
	    }
	}
	folder.delete();
    }

    /**
     *
     */
    public AflAgentTest() {
    }

    /**
     *
     */
    @Before
    public void setUp() {
	agent = new AFLAgent();
	// TODO
	ServerManager.getInstance().clear();
	ServerManager
		.getInstance()
		.addServer(
			new TLSServer(
				"127.0.0.1",
				4433,
				"AFL/openssl-1.1.0-pre5/myOpenssl/bin/openssl s_server -naccept 1 -key /home/ic0ns/key.pem -cert /home/ic0ns/cert.pem -accept [port]",
				"ACCEPT", "JUNIT/"));
	server = ServerManager.getInstance().getFreeServer();

    }

    /**
     *
     */
    @After
    public void tearDown() {
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
    @Test(expected = RuntimeException.class)
    public void testDoubleStart() {
	agent.applicationStart(server);
	agent.applicationStart(server);
    }

    /**
     *
     */
    @Test(expected = RuntimeException.class)
    public void testNotStarted() {
	agent.applicationStop(server);
    }

    /**
     *
     */
    @Test(expected = RuntimeException.class)
    public void testDoubleStop() {
	agent.applicationStart(server);
	agent.applicationStop(server);
	agent.applicationStop(server);

    }

    // TODO Collect Results Test
    private static final Logger LOG = Logger.getLogger(AflAgentTest.class.getName());

}
