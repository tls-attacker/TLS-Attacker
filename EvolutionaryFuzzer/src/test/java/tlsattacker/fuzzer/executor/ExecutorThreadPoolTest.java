/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.executor;

import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import java.io.IOException;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ExecutorThreadPoolTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    /**
     *
     */
    public ExecutorThreadPoolTest() {
    }

    /**
     *
     * @throws java.io.IOException
     */
    @Test
    public void testConstructor() throws IOException {
        EvolutionaryFuzzerConfig config = new EvolutionaryFuzzerConfig();
        config.setOutputFolder(tempFolder.newFolder().getAbsolutePath());
        config.setConfigFolder(tempFolder.newFolder().getAbsolutePath());
        // config.createFolders();
        // Todo has to be redone
        // AnalyzerThread thread = new AnalyzerThread(new RuleAnalyzer(config));
        // thread.start();
        // ExecutorThreadPool pool = new ExecutorThreadPool(5, new
        // SimpleMutator(config, new FixedCertificateMutator(config)),
        // config, thread);
        // assertTrue("Failure: Pool is not stopped on creation",
        // pool.isStopped());
    }

    /**
     *
     */
    public void tearDown() {
    }

}
