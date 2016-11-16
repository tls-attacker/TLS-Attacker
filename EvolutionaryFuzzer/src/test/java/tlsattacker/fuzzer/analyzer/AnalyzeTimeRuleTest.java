/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer;

import tlsattacker.fuzzer.analyzer.rules.AnalyzeTimeRule;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.graphs.BranchTrace;
import tlsattacker.fuzzer.result.AgentResult;
import tlsattacker.fuzzer.testvector.TestVector;
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
public class AnalyzeTimeRuleTest {

    /**
     *
     */
    private AnalyzeTimeRule rule;

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();
    
    /**
     *
     */
    public AnalyzeTimeRuleTest() {
    }

    /**
     *
     */
    @Before
    public void setUp() throws IOException {
        EvolutionaryFuzzerConfig config = new EvolutionaryFuzzerConfig();
        config.setOutputFolder(tempFolder.newFolder().getAbsolutePath());
        config.setConfigFolder(tempFolder.newFolder().getAbsolutePath());
        config.createFolders();
        rule = new AnalyzeTimeRule(config);

    }

    /**
     * Test of applies method, of class AnalyzeTimeRule.
     */
    @Test
    public void testApplys() {
        AgentResult result = new AgentResult(false, false, 1000, 2000, new BranchTrace(), new TestVector(), "unittest.id", null);
        assertTrue(rule.applies(result));
    }

    /**
     * Test of onApply method, of class AnalyzeTimeRule.
     */
    @Test
    public void testOnApply() {
        AgentResult result = new AgentResult(false, false, 1000, 2000, new BranchTrace(), new TestVector(), "unittest.id", null);
        rule.onApply(result);
    }

    /**
     * Test of onDecline method, of class AnalyzeTimeRule.
     */
    @Test
    public void testOnDecline() {
        rule.onDecline(null);
    }

    /**
     * Test of report method, of class AnalyzeTimeRule.
     */
    @Test
    public void testReport() {
        AgentResult result = new AgentResult(false, false, 1000, 2000, new BranchTrace(), new TestVector(), "unittest.id", null);
        assertNull("Failure: Report should be null!", rule.report());
        rule.onApply(result);
        assertNotNull("Failure: Report should not be null!", rule.report());
    }

    /**
     * Test of getConfig method, of class AnalyzeTimeRule.
     */
    @Test
    public void testGetConfig() {
        assertNotNull(rule.getConfig());
    }

    /**
     * Test of getExecutedTimeTotal method, of class AnalyzeTimeRule.
     */
    @Test
    public void testGetExecutedTimeTotal() {
        AgentResult result = new AgentResult(false, false, 1000, 2000, new BranchTrace(), new TestVector(), "unittest.id", null);
        rule.onApply(result);
        assertTrue(rule.getExecutedTimeTotal() == 1000);
        rule.onApply(result);
        assertTrue(rule.getExecutedTimeTotal() == 2000);
    }

    /**
     * Test of getNumberExecutedTraces method, of class AnalyzeTimeRule.
     */
    @Test
    public void testGetNumberExecutedTraces() {
        AgentResult result = new AgentResult(false, false, 1000, 2000, new BranchTrace(), new TestVector(), "unittest.id", null);
        rule.onApply(result);
        assertTrue(rule.getNumberExecutedTraces() == 1);
        rule.onApply(result);
        assertTrue(rule.getNumberExecutedTraces() == 2);
    }

    /**
     * Test of getSlowestTime method, of class AnalyzeTimeRule.
     */
    @Test
    public void testGetSlowestTime() {
        AgentResult result = new AgentResult(false, false, 1000, 2000, new BranchTrace(), new TestVector(), "unittest.id", null);
        rule.onApply(result);
        assertTrue(rule.getSlowestTime() == 1000);
        result = new AgentResult(false, false, 1000, 4000, new BranchTrace(), new TestVector(), "unittest.id", null);
        rule.onApply(result);
        assertTrue(rule.getSlowestTime() == 3000);
    }

    /**
     * Test of getFastestTime method, of class AnalyzeTimeRule.
     */
    @Test
    public void testGetFastestTime() {
        AgentResult result = new AgentResult(false, false, 1000, 2000, new BranchTrace(), new TestVector(), "unittest.id", null);
        rule.onApply(result);
        assertTrue(rule.getFastestTime() == 1000);
        result = new AgentResult(false, false, 1000, 4000, new BranchTrace(), new TestVector(), "unittest.id", null);
        rule.onApply(result);
        assertTrue(rule.getFastestTime() == 1000);
    }

    private static final Logger LOG = Logger.getLogger(AnalyzeTimeRuleTest.class.getName());

}
