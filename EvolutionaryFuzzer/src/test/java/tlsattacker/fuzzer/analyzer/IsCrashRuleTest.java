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
import tlsattacker.fuzzer.result.AgentResult;
import tlsattacker.fuzzer.testvector.TestVector;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import de.rub.nds.tlsattacker.util.FileHelper;
import java.io.File;
import java.io.IOException;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class IsCrashRuleTest {

    /**
     *
     */
    private IsCrashRule rule;

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();
    
    private EvolutionaryFuzzerConfig config;
    
    /**
     *
     */
    public IsCrashRuleTest() {
    }

    /**
     *
     */
    @Before
    public void setUp() throws IOException {
        config = new EvolutionaryFuzzerConfig();
        config.setOutputFolder(tempFolder.newFolder().getAbsolutePath());
        config.setConfigFolder(tempFolder.newFolder().getAbsolutePath());
        config.createFolders();
        rule = new IsCrashRule(config);
    }

    /**
     * Test of applies method, of class IsCrashRule.
     */
    @Test
    public void testApplys() {
        AgentResult result = new AgentResult(true, false, 9, 10, new BranchTrace(), new TestVector(new WorkflowTrace(), null,
                null, ExecutorType.TLS, null), "unit2.test", null);
        assertTrue(rule.applies(result));
        result = new AgentResult(false, false, 9, 10, new BranchTrace(), new TestVector(new WorkflowTrace(), null, null,
                ExecutorType.TLS, null), "unit2.test", null);
        assertFalse(rule.applies(result));

    }

    /**
     * Test of onApply method, of class IsCrashRule.
     */
    @Test
    public void testOnApply() {
        AgentResult result = new AgentResult(true, false, 9, 10, new BranchTrace(), new TestVector(new WorkflowTrace(), null,
                null, ExecutorType.TLS, null), "unit2.test", null);
        rule.onApply(result);
        assertTrue(new File(config.getOutputFolder() + rule.getConfig().getOutputFolder()).listFiles().length == 1);
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
        AgentResult result = new AgentResult(true, false, 9, 10, new BranchTrace(), new TestVector(new WorkflowTrace(), null,
                null, ExecutorType.TLS, null), "unit2.test", null);
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
