/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer.rule;

import tlsattacker.fuzzer.analyzer.rule.IsGoodRule;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.instrumentation.Branch;
import tlsattacker.fuzzer.result.AgentResult;
import tlsattacker.fuzzer.testvector.TestVector;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;
import tlsattacker.fuzzer.instrumentation.EmptyInstrumentationMap;
import tlsattacker.fuzzer.instrumentation.InstrumentationMap;
import tlsattacker.fuzzer.instrumentation.PinInstrumentationMap;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class IsGoodRuleTest {

    private IsGoodRule rule;

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private EvolutionaryFuzzerConfig config;

    /**
     *
     */
    public IsGoodRuleTest() {
    }

    /**
     *
     * @throws java.io.IOException
     */
    @Before
    public void setUp() throws IOException {
        config = new EvolutionaryFuzzerConfig();
        config.setSerialize(true);
        config.setOutputFolder(tempFolder.newFolder().getAbsolutePath());
        config.setConfigFolder(tempFolder.newFolder().getAbsolutePath());
        config.createFolders();
        rule = new IsGoodRule(config);
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
        Map<Branch, Branch> branchMap = new HashMap<>();
        Branch tempBranch = new Branch(1, 2);
        branchMap.put(tempBranch, tempBranch);
        tempBranch = new Branch(2, 3);
        branchMap.put(tempBranch, tempBranch);
        InstrumentationMap instrumentationMap = new PinInstrumentationMap(verticesSet, branchMap);
        AgentResult result = new AgentResult(false, false, 0, 5, instrumentationMap, new TestVector(
                new WorkflowTrace(), null, null, ExecutorType.TLS, null), "unit1.test", null);
        assertTrue(rule.applies(result));
        assertFalse(rule.applies(result)); // The same trace should not apply
        // twice
        branchMap = new HashMap<>();
        tempBranch = new Branch(1, 3);
        branchMap.put(tempBranch, tempBranch);
        tempBranch = new Branch(1, 2);
        branchMap.put(tempBranch, tempBranch);
        tempBranch = new Branch(2, 3);
        branchMap.put(tempBranch, tempBranch);
        instrumentationMap = new PinInstrumentationMap(verticesSet, branchMap);
        result = new AgentResult(false, false, 0, 5, instrumentationMap, new TestVector(new WorkflowTrace(), null,
                null, ExecutorType.TLS, null), "unit1.test", null);
        assertTrue(rule.applies(result));
        verticesSet = new HashSet<>();
        verticesSet.add(1l);
        verticesSet.add(2l);
        verticesSet.add(3l);
        verticesSet.add(4l);
        instrumentationMap = new PinInstrumentationMap(verticesSet, branchMap);
        result = new AgentResult(false, false, 0, 5, instrumentationMap, new TestVector(new WorkflowTrace(), null,
                null, ExecutorType.TLS, null), "unit1.test", null);
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
        Map<Branch, Branch> edgeMap = new HashMap<>();
        Branch tempEdge = new Branch(1, 2);
        edgeMap.put(tempEdge, tempEdge);
        tempEdge = new Branch(2, 3);
        edgeMap.put(tempEdge, tempEdge);
        InstrumentationMap trace = new PinInstrumentationMap(verticesSet, edgeMap);
        AgentResult result = new AgentResult(false, false, 0, 5, trace, new TestVector(new WorkflowTrace(), null, null,
                ExecutorType.TLS, null), "unit1.test", null);
        rule.onApply(result);
        assertTrue(result.isGoodTrace());
        assertTrue(new File(config.getOutputFolder() + rule.getConfig().getOutputFolder()).listFiles().length == 1);

    }

    /**
     * Test of getInstrumentationMap method, of class IsGoodRule.
     */
    @Test
    public void testGetBranchTrace() {
        Set<Long> verticesSet = new HashSet<>();
        verticesSet.add(1l);
        verticesSet.add(2l);
        verticesSet.add(3l);
        Map<Branch, Branch> edgeMap = new HashMap<>();
        Branch tempEdge = new Branch(1, 2);
        edgeMap.put(tempEdge, tempEdge);
        tempEdge = new Branch(2, 3);
        edgeMap.put(tempEdge, tempEdge);
        InstrumentationMap trace = new PinInstrumentationMap(verticesSet, edgeMap);
        AgentResult result = new AgentResult(false, false, 0, 5, trace, new TestVector(new WorkflowTrace(), null, null,
                ExecutorType.TLS, null), "unit1.test", null);
        rule.applies(result);
        trace = rule.getInstrumentationMap();
        assertNotNull(result);

        // assertTrue(trace.getVerticesCount() == 3);
        // assertTrue(trace.getBranchCount() == 2);
    }

    /**
     * Test of onDecline method, of class IsGoodRule.
     */
    @Test
    public void testOnDecline() {
        AgentResult result = new AgentResult(false, false, 0, 2, null, null, null, null);
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
        Map<Branch, Branch> edgeMap = new HashMap<>();
        Branch tempEdge = new Branch(1, 2);
        edgeMap.put(tempEdge, tempEdge);
        tempEdge = new Branch(2, 3);
        edgeMap.put(tempEdge, tempEdge);
        InstrumentationMap trace = new PinInstrumentationMap(verticesSet, edgeMap);
        AgentResult result = new AgentResult(false, false, 0, 5, trace, new TestVector(new WorkflowTrace(), null, null,
                ExecutorType.TLS, null), "unit1.test", null);
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

}
