/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Result;

import Analyzer.IsCrashRule;
import Config.ConfigManager;
import Config.EvolutionaryFuzzerConfig;
import Graphs.BranchTrace;
import TestVector.TestVector;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.util.FileHelper;
import java.io.File;
import java.util.ArrayList;
import org.junit.After;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ResultContainerTest {

    public ResultContainerTest() {
    }
    @Before
    public void setUp() {
	EvolutionaryFuzzerConfig config = new EvolutionaryFuzzerConfig();
	config.setOutputFolder("unit_test_output/");
	config.setConfigFolder("unit_test_config/");
        ConfigManager.getInstance().setConfig(config);
    }

    @After
    public void tearDown() {
	FileHelper.deleteFolder(new File("unit_test_output"));
	FileHelper.deleteFolder(new File("unit_test_config"));
    }
    /**
     * Test of getInstance method, of class ResultContainer.
     */
    @Test
    public void testGetInstance() {
	ResultContainer result = ResultContainer.getInstance();
	assertNotNull(result);
    }

    /**
     * Test of commit method, of class ResultContainer.
     */
    @Test
    public void testCommit() {

	Result result = new Result(true, true, 0, System.currentTimeMillis(), new BranchTrace(), new TestVector(
		new WorkflowTrace(), null, null), new TestVector(new WorkflowTrace(), null, null), "test.unit");// TODO
														// Delete
														// Testfiles
	ResultContainer instance = ResultContainer.getInstance();
	instance.commit(result);

    }
}
