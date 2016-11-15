/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.executor;

import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.executor.ExecutorThreadPool;
import tlsattacker.fuzzer.mutator.certificate.FixedCertificateMutator;
import tlsattacker.fuzzer.mutator.SimpleMutator;
import de.rub.nds.tlsattacker.util.FileHelper;
import java.io.File;
import java.io.IOException;
import java.util.logging.Logger;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;
import tlsattacker.fuzzer.analyzer.AnalyzerThread;
import tlsattacker.fuzzer.analyzer.RuleAnalyzer;

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
     */
    @Test
    public void testConstructor() throws IOException {
        EvolutionaryFuzzerConfig config = new EvolutionaryFuzzerConfig();
        config.setOutputFolder(tempFolder.newFolder().getAbsolutePath());
        config.setConfigFolder(tempFolder.newFolder().getAbsolutePath());
        //config.createFolders();
        //Todo has to be redone
        //AnalyzerThread thread = new AnalyzerThread(new RuleAnalyzer(config));
        //thread.start();
        // ExecutorThreadPool pool = new ExecutorThreadPool(5, new SimpleMutator(config, new FixedCertificateMutator(config)),
        //        config, thread);
        //  assertTrue("Failure: Pool is not stopped on creation", pool.isStopped());
    }

    /**
     *
     */
    public void tearDown() {
    }

    private static final Logger LOG = Logger.getLogger(ExecutorThreadPoolTest.class.getName());

}
