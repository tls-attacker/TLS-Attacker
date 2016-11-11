/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer;

import tlsattacker.fuzzer.analyzer.rules.IsCrashRule;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.graphs.BranchTrace;
import tlsattacker.fuzzer.result.Result;
import tlsattacker.fuzzer.testvector.TestVector;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import de.rub.nds.tlsattacker.util.FileHelper;
import java.io.File;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class IsCrashRuleTest {

    /**
     *
     */
    private IsCrashRule rule;

    /**
     *
     */
    public IsCrashRuleTest() {
    }

    /**
     *
     */
    @Before
    public void setUp() {
        EvolutionaryFuzzerConfig config = new EvolutionaryFuzzerConfig();
        config.setOutputFolder("unit_test_output/");
        config.setConfigFolder("unit_test_config/");
        config.createFolders();
        rule = new IsCrashRule(config);
    }

    /**
     *
     */
    @After
    public void tearDown() {
        FileHelper.deleteFolder(new File("unit_test_output"));
        FileHelper.deleteFolder(new File("unit_test_config"));
    }

    /**
     * Test of applies method, of class IsCrashRule.
     */
    @Test
    public void testApplys() {
        Result result = new Result(true, false, 9, 10, new BranchTrace(), new TestVector(new WorkflowTrace(), null,
                null, ExecutorType.TLS, null), "unit2.test");
        assertTrue(rule.applies(result));
        result = new Result(false, false, 9, 10, new BranchTrace(), new TestVector(new WorkflowTrace(), null, null,
                ExecutorType.TLS, null), "unit2.test");
        assertFalse(rule.applies(result));

    }

    /**
     * Test of onApply method, of class IsCrashRule.
     */
    @Test
    public void testOnApply() {
        Result result = new Result(true, false, 9, 10, new BranchTrace(), new TestVector(new WorkflowTrace(), null,
                null, ExecutorType.TLS, null), "unit2.test");
        rule.onApply(result);
        assertTrue(new File("unit_test_output/" + rule.getConfig().getOutputFolder()).listFiles().length == 1);
    }

    /**
     * Test of onDecline method, of class IsCrashRule.
     */
    @Test
    public void testOnDecline() {
        rule.onDecline(null);
    }

    /**
     * Test of report method, of class IsCrashRule.
     */
    @Test
    public void testReport() {
        assertNull(rule.report());
        Result result = new Result(true, false, 9, 10, new BranchTrace(), new TestVector(new WorkflowTrace(), null,
                null, ExecutorType.TLS, null), "unit2.test");
        rule.onApply(result);
        assertNotNull(rule.report());
    }

    /**
     * Test of getConfig method, of class IsCrashRule.
     */
    @Test
    public void testGetConfig() {
        assertNotNull(rule.getConfig());
    }

    private static final Logger LOG = Logger.getLogger(IsCrashRuleTest.class.getName());

}
