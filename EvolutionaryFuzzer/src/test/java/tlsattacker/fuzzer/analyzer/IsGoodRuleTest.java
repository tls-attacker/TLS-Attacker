/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer;

import tlsattacker.fuzzer.analyzer.rules.IsGoodRule;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.graphs.BranchTrace;
import tlsattacker.fuzzer.graphs.Edge;
import tlsattacker.fuzzer.result.Result;
import tlsattacker.fuzzer.testvector.TestVector;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import de.rub.nds.tlsattacker.util.FileHelper;
import java.io.File;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class IsGoodRuleTest {

    /**
     *
     */
    private IsGoodRule rule;

    /**
     *
     */
    public IsGoodRuleTest() {
    }

    /**
     *
     */
    @Before
    public void setUp() {
	EvolutionaryFuzzerConfig config = new EvolutionaryFuzzerConfig();
	config.setSerialize(true);
	config.setOutputFolder("unit_test_output/");
	config.setConfigFolder("unit_test_config/");
	rule = new IsGoodRule(config);
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
     * Test of applies method, of class IsGoodRule.
     */
    @Test
    public void testApplys() {
	Set<Long> verticesSet = new HashSet<>();
	verticesSet.add(1l);
	verticesSet.add(2l);
	verticesSet.add(3l);
	Map<Edge, Edge> edgeMap = new HashMap<>();
	Edge tempEdge = new Edge(1, 2);
	edgeMap.put(tempEdge, tempEdge);
	tempEdge = new Edge(2, 3);
	edgeMap.put(tempEdge, tempEdge);
	BranchTrace trace = new BranchTrace(verticesSet, edgeMap);
	Result result = new Result(false, false, 0, 5, trace, new TestVector(new WorkflowTrace(), null, null,
		ExecutorType.TLS, null), "unit1.test");
	assertTrue(rule.applies(result));
	assertFalse(rule.applies(result)); // The same trace should not apply
					   // twice
	tempEdge = new Edge(1, 3);
	edgeMap.put(tempEdge, tempEdge);
	trace = new BranchTrace(verticesSet, edgeMap);
	result = new Result(false, false, 0, 5, trace, new TestVector(new WorkflowTrace(), null, null,
		ExecutorType.TLS, null), "unit1.test");
	assertTrue(rule.applies(result));
	verticesSet.add(4l);
	trace = new BranchTrace(verticesSet, edgeMap);
	result = new Result(false, false, 0, 5, trace, new TestVector(new WorkflowTrace(), null, null,
		ExecutorType.TLS, null), "unit1.test");
	assertTrue(rule.applies(result));
    }

    /**
     * Test of onApply method, of class IsGoodRule.
     */
    @Test
    public void testOnApply() {
	Set<Long> verticesSet = new HashSet<>();
	verticesSet.add(1l);
	verticesSet.add(2l);
	verticesSet.add(3l);
	Map<Edge, Edge> edgeMap = new HashMap<>();
	Edge tempEdge = new Edge(1, 2);
	edgeMap.put(tempEdge, tempEdge);
	tempEdge = new Edge(2, 3);
	edgeMap.put(tempEdge, tempEdge);
	BranchTrace trace = new BranchTrace(verticesSet, edgeMap);
	Result result = new Result(false, false, 0, 5, trace, new TestVector(new WorkflowTrace(), null, null,
		ExecutorType.TLS, null), "unit1.test");
	rule.onApply(result);
	assertTrue(result.isGoodTrace());
	assertTrue(new File("unit_test_output/" + rule.getConfig().getOutputFolder()).listFiles().length == 1);

    }

    /**
     * Test of getBranchTrace method, of class IsGoodRule.
     */
    @Test
    public void testGetBranchTrace() {
	Set<Long> verticesSet = new HashSet<>();
	verticesSet.add(1l);
	verticesSet.add(2l);
	verticesSet.add(3l);
	Map<Edge, Edge> edgeMap = new HashMap<>();
	Edge tempEdge = new Edge(1, 2);
	edgeMap.put(tempEdge, tempEdge);
	tempEdge = new Edge(2, 3);
	edgeMap.put(tempEdge, tempEdge);
	BranchTrace trace = new BranchTrace(verticesSet, edgeMap);
	Result result = new Result(false, false, 0, 5, trace, new TestVector(new WorkflowTrace(), null, null,
		ExecutorType.TLS, null), "unit1.test");
	rule.applies(result);
	trace = rule.getBranchTrace();
	assertNotNull(result);

	assertTrue(trace.getVerticesCount() == 3);
	assertTrue(trace.getBranchCount() == 2);
    }

    /**
     * Test of onDecline method, of class IsGoodRule.
     */
    @Test
    public void testOnDecline() {
	Result result = new Result(false, false, 0, 2, null, null, null);
	assertNull(result.isGoodTrace());
	rule.onDecline(result);
	assertFalse(result.isGoodTrace());
    }

    /**
     * Test of report method, of class IsGoodRule.
     */
    @Test
    public void testReport() {
	Set<Long> verticesSet = new HashSet<>();
	verticesSet.add(1l);
	verticesSet.add(2l);
	verticesSet.add(3l);
	Map<Edge, Edge> edgeMap = new HashMap<>();
	Edge tempEdge = new Edge(1, 2);
	edgeMap.put(tempEdge, tempEdge);
	tempEdge = new Edge(2, 3);
	edgeMap.put(tempEdge, tempEdge);
	BranchTrace trace = new BranchTrace(verticesSet, edgeMap);
	Result result = new Result(false, false, 0, 5, trace, new TestVector(new WorkflowTrace(), null, null,
		ExecutorType.TLS, null), "unit1.test");
	rule.onApply(result);
	assertNotNull(rule.report());
    }

    /**
     * Test of getConfig method, of class IsGoodRule.
     */
    @Test
    public void testGetConfig() {
	assertNotNull(rule.getConfig());
    }

    private static final Logger LOG = Logger.getLogger(IsGoodRuleTest.class.getName());

}
