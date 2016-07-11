/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package GlobalBranchTreeTests;

import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import tls.rub.evolutionaryfuzzer.BasicAFLAgent;

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
    }

    BasicAFLAgent agent = null;

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
	agent = new BasicAFLAgent();
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

	agent.onApplicationStart();
	agent.onApplicationStop();
    }

    /**
     *
     */
    @Test(expected = RuntimeException.class)
    public void testDoubleStart() {
	agent.onApplicationStart();
	agent.onApplicationStart();
    }

    /**
     *
     */
    @Test(expected = RuntimeException.class)
    public void testNotStarted() {
	agent.onApplicationStop();
    }

    /**
     *
     */
    @Test(expected = RuntimeException.class)
    public void testDoubleStop() {
	agent.onApplicationStart();
	agent.onApplicationStop();
	agent.onApplicationStop();

    }

    // TODO Collect Results Test
    private static final Logger LOG = Logger.getLogger(AflAgentTest.class.getName());

}
