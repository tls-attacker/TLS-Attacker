/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Analyzer;

import Config.Analyzer.AnalyzeTimeRuleConfig;
import Config.EvolutionaryFuzzerConfig;
import Graphs.BranchTrace;
import Result.Result;
import TestVector.TestVector;
import de.rub.nds.tlsattacker.util.FileHelper;
import java.io.File;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author ic0ns
 */
public class AnalyzeTimeRuleTest {
    private AnalyzeTimeRule rule;

    public AnalyzeTimeRuleTest() {
    }

    @Before
    public void setUp() {
	EvolutionaryFuzzerConfig config = new EvolutionaryFuzzerConfig();
	config.setOutputFolder("unit_test_output/");
	config.setConfigFolder("unit_test_config/");
	rule = new AnalyzeTimeRule(config);

    }

    @After
    public void tearDown() {
	FileHelper.deleteFolder(new File("unit_test_output"));
	FileHelper.deleteFolder(new File("unit_test_config"));

    }

    /**
     * Test of applys method, of class AnalyzeTimeRule.
     */
    @Test
    public void testApplys() {
	Result result = new Result(false, false, 1000, 2000, new BranchTrace(), new TestVector(), new TestVector(),
		"unittest.id");
	assertTrue(rule.applys(result));
    }

    /**
     * Test of onApply method, of class AnalyzeTimeRule.
     */
    @Test
    public void testOnApply() {
	Result result = new Result(false, false, 1000, 2000, new BranchTrace(), new TestVector(), new TestVector(),
		"unittest.id");
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
	Result result = new Result(false, false, 1000, 2000, new BranchTrace(), new TestVector(), new TestVector(),
		"unittest.id");
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
	Result result = new Result(false, false, 1000, 2000, new BranchTrace(), new TestVector(), new TestVector(),
		"unittest.id");
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
	Result result = new Result(false, false, 1000, 2000, new BranchTrace(), new TestVector(), new TestVector(),
		"unittest.id");
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
	Result result = new Result(false, false, 1000, 2000, new BranchTrace(), new TestVector(), new TestVector(),
		"unittest.id");
	rule.onApply(result);
	assertTrue(rule.getSlowestTime() == 1000);
	result = new Result(false, false, 1000, 4000, new BranchTrace(), new TestVector(), new TestVector(),
		"unittest.id");
	rule.onApply(result);
	assertTrue(rule.getSlowestTime() == 3000);
    }

    /**
     * Test of getFastestTime method, of class AnalyzeTimeRule.
     */
    @Test
    public void testGetFastestTime() {
	Result result = new Result(false, false, 1000, 2000, new BranchTrace(), new TestVector(), new TestVector(),
		"unittest.id");
	rule.onApply(result);
	assertTrue(rule.getFastestTime() == 1000);
	result = new Result(false, false, 1000, 4000, new BranchTrace(), new TestVector(), new TestVector(),
		"unittest.id");
	rule.onApply(result);
	assertTrue(rule.getFastestTime() == 1000);
    }

}
