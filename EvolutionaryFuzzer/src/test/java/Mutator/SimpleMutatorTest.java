/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Mutator;

import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import Config.EvolutionaryFuzzerConfig;
import Mutator.SimpleMutator;

/**
 * 
 * @author ic0ns
 */
public class SimpleMutatorTest {
    private static final Logger LOG = Logger.getLogger(SimpleMutatorTest.class.getName());

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

    /**
     *
     */
    public SimpleMutatorTest() {
    }

    /**
     *
     */
    @Before
    public void setUp() {
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
    public void testMutation() {
	EvolutionaryFuzzerConfig config = new EvolutionaryFuzzerConfig();
	SimpleMutator mutator = new SimpleMutator(config, new FixedCertificateMutator());
	mutator.getNewMutation();
    }
}
