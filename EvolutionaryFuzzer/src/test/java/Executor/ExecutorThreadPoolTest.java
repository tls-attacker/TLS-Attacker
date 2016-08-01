/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Executor;

import Config.EvolutionaryFuzzerConfig;
import Executor.ExecutorThreadPool;
import Mutator.FixedCertificateMutator;
import Mutator.SimpleMutator;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ExecutorThreadPoolTest {

    public ExecutorThreadPoolTest() {
    }

    @Test
    public void testConstructor() {
	EvolutionaryFuzzerConfig config = new EvolutionaryFuzzerConfig();

	ExecutorThreadPool pool = new ExecutorThreadPool(5, new SimpleMutator(config, new FixedCertificateMutator()),
		config);
	assertTrue("Failure: Pool is not stopped on creation", pool.isStopped());
    }
}
