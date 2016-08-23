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
import Config.EvolutionaryFuzzerConfig;
import Mutator.Certificate.FixedCertificateMutator;
import Server.ServerSerializer;
import Server.TLSServer;
import TestHelper.UnitTestCertificateMutator;
import TestVector.ServerCertificateKeypair;
import de.rub.nds.tlsattacker.tls.config.ServerCertificateKey;
import de.rub.nds.tlsattacker.util.FileHelper;
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
    @AfterClass
    public static void tearDownClass() {

	File f = new File("JUNIT/");
	FileHelper.deleteFolder(f);

    }

    private AFLAgent agent = null;
    private TLSServer server = null;
    private UnitTestCertificateMutator mut = null;
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
        EvolutionaryFuzzerConfig config = new EvolutionaryFuzzerConfig();
	config.setOutputFolder("unit_test_output/");
	config.setConfigFolder("unit_test_config/");
        ConfigManager.getInstance().setConfig(config);
	mut = new UnitTestCertificateMutator();
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
