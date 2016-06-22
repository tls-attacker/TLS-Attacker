/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package GlobalBranchTreeTests;

import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import tls.rub.evolutionaryfuzzer.EvolutionaryFuzzerConfig;
import tls.rub.evolutionaryfuzzer.SimpleMutator;


public class SimpleMutatorTest
{

    /**
     *
     */
    public SimpleMutatorTest()
    {
    }

    /**
     *
     */
    @BeforeClass
    public static void setUpClass()
    {
    }

    /**
     *
     */
    @AfterClass
    public static void tearDownClass()
    {
    }

    /**
     *
     */
    @Before
    public void setUp()
    {
    }

    /**
     *
     */
    @After
    public void tearDown()
    {
    }

    /**
     *
     */
    @Test
    public void testMutation()
    {
        ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler("client");
        TlsContext tmpTlsContext = configHandler.initializeTlsContext(new EvolutionaryFuzzerConfig());

        SimpleMutator mutator = new SimpleMutator(tmpTlsContext);
        mutator.getNewMutation();
    }
    private static final Logger LOG = Logger.getLogger(SimpleMutatorTest.class.getName());
}
