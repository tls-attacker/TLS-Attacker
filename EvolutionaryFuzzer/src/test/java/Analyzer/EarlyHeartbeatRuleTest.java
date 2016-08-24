/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Analyzer;

import Config.Analyzer.EarlyHeartbeatRuleConfig;
import Config.EvolutionaryFuzzerConfig;
import Graphs.BranchTrace;
import Result.Result;
import TestVector.TestVector;
import de.rub.nds.tlsattacker.eap.ClientHello;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.util.FileHelper;
import java.io.File;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author ic0ns
 */
public class EarlyHeartbeatRuleTest {

    private EarlyHeartbeatRule rule;

    public EarlyHeartbeatRuleTest() {

    }

    @Before
    public void setUp() {
	EvolutionaryFuzzerConfig config = new EvolutionaryFuzzerConfig();
	config.setOutputFolder("unit_test_output/");
	config.setConfigFolder("unit_test_config/");
	rule = new EarlyHeartbeatRule(config);
    }

    @After
    public void tearDown() {
	FileHelper.deleteFolder(new File("unit_test_output"));
	FileHelper.deleteFolder(new File("unit_test_config"));

    }

    /**
     * Test of applys method, of class EarlyHeartbeatRule.
     */
    @Test
    public void testApplys() {
	WorkflowTrace trace = new WorkflowTrace();
	trace.add(new ClientHelloMessage(ConnectionEnd.CLIENT));
	trace.add(new HeartbeatMessage(ConnectionEnd.CLIENT));
	trace.add(new HeartbeatMessage(ConnectionEnd.SERVER));
	Result result = new Result(false, false, 1000, 2000, new BranchTrace(),
		new TestVector(trace, null, null, null), new TestVector(trace, null, null, null), "unittest.id");
	assertTrue(rule.applys(result));
	trace.add(new FinishedMessage(ConnectionEnd.SERVER));
	assertTrue(rule.applys(result));
	trace = new WorkflowTrace();
	trace.add(new ClientHelloMessage(ConnectionEnd.CLIENT));
	trace.add(new FinishedMessage(ConnectionEnd.SERVER));
	trace.add(new HeartbeatMessage(ConnectionEnd.SERVER));
	result = new Result(false, false, 1000, 2000, new BranchTrace(), new TestVector(trace, null, null, null),
		new TestVector(trace, null, null, null), "unittest.id");
	assertFalse(rule.applys(result));
	trace = new WorkflowTrace();
	trace.add(new ClientHelloMessage(ConnectionEnd.CLIENT));
	trace.add(new FinishedMessage(ConnectionEnd.SERVER));
	result = new Result(false, false, 1000, 2000, new BranchTrace(), new TestVector(trace, null, null, null),
		new TestVector(trace, null, null, null), "unittest.id");
	assertFalse(rule.applys(result));
	result = new Result(false, false, 1000, 2000, new BranchTrace(), new TestVector(trace, null, null, null),
		new TestVector(trace, null, null, null), "unittest.id");
	trace = new WorkflowTrace();
	trace.add(new ClientHelloMessage(ConnectionEnd.CLIENT));
	trace.add(new ServerHelloMessage(ConnectionEnd.SERVER));
	assertFalse(rule.applys(result));
    }

    /**
     * Test of onApply method, of class EarlyHeartbeatRule.
     */
    @Test
    public void testOnApply() {
	// TODO we only tested if the onApply Method did not crash, not if it
	// saved the workflowtrace
	WorkflowTrace trace = new WorkflowTrace();
	trace.add(new ClientHelloMessage(ConnectionEnd.CLIENT));
	trace.add(new HeartbeatMessage(ConnectionEnd.CLIENT));
	trace.add(new HeartbeatMessage(ConnectionEnd.SERVER));
	Result result = new Result(false, false, 1000, 2000, new BranchTrace(),
		new TestVector(trace, null, null, null), new TestVector(trace, null, null, null), "unittest.id");
	rule.onApply(result);
    }

    /**
     * Test of onDecline method, of class EarlyHeartbeatRule.
     */
    @Test
    public void testOnDecline() {
	rule.onDecline(null);
    }

    /**
     * Test of report method, of class EarlyHeartbeatRule.
     */
    @Test
    public void testReport() {
	assertNull(rule.report());
	WorkflowTrace trace = new WorkflowTrace();
	trace.add(new ClientHelloMessage(ConnectionEnd.CLIENT));
	trace.add(new HeartbeatMessage(ConnectionEnd.CLIENT));
	trace.add(new HeartbeatMessage(ConnectionEnd.SERVER));
	Result result = new Result(false, false, 1000, 2000, new BranchTrace(),
		new TestVector(trace, null, null, null), new TestVector(trace, null, null, null), "unittest.id");
	rule.onApply(result);
	assertNotNull(rule.report());
    }

    /**
     * Test of getConfig method, of class EarlyHeartbeatRule.
     */
    @Test
    public void testGetConfig() {
	assertNotNull(rule.getConfig());
    }

}
