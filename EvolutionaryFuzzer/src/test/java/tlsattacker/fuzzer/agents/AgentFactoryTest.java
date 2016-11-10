/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.agents;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.exceptions.IllegalAgentException;

/**
 *
 * @author ic0ns
 */
public class AgentFactoryTest {
    
    public AgentFactoryTest() {
    }
    
    @Before
    public void setUp() {
    }

    /**
     * Test of generateAgent method, of class AgentFactory.
     */
    @Test
    public void testGenerateAgent() throws IllegalAgentException {
        EvolutionaryFuzzerConfig config = new EvolutionaryFuzzerConfig();
        config.setAgent("BLIND");
        Agent agent = AgentFactory.generateAgent(config, null);
        assertTrue(agent instanceof BlindAgent);
        config.setAgent("PIN");
        agent = AgentFactory.generateAgent(config, null);
        assertTrue(agent instanceof PINAgent);
        config.setAgent("AFL");
        agent = AgentFactory.generateAgent(config, null);
        assertTrue(agent instanceof AFLAgent);
        config.setAgent("NOT A REAL AGENT");
        try
        {
            agent = AgentFactory.generateAgent(config, null);
            fail("Undefined Agent did not throw an Exception");
        }
        catch(IllegalAgentException E)
        {
            assertTrue(E != null);
        }
    }
    
}
