/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Agent;

import java.io.File;
import java.util.logging.Logger;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Test;
import Agents.AFLAgent;
import Config.ConfigManager;
import Mutator.Certificate.FixedCertificateMutator;
import Server.ServerSerializer;
import Server.TLSServer;
import TestVector.ServerCertificateKeypair;
import de.rub.nds.tlsattacker.tls.config.ServerCertificateKey;
import java.util.logging.Level;
import org.junit.After;
import org.junit.Assert;

/**
 * 
 * @author ic0ns
 */
public class AflAgentTest {
    // TODO Collect Results Test
    private static final Logger LOG = Logger.getLogger(AflAgentTest.class.getName());

    /**
     *
     */
    @AfterClass
    public static void tearDownClass() {

	File f = new File("JUNIT/");
	deleteFolder(f);

    }

    public static void deleteFolder(File folder) {
	File[] files = folder.listFiles();
	if (files != null) {
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

    private AFLAgent agent = null;
    private TLSServer server = null;
    private FixedCertificateMutator mut = null;
    private ServerCertificateKeypair pair = null;

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
	mut = new FixedCertificateMutator();
	pair = mut.getServerCertificateKeypair();
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

}
