/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Analyzer;

import Config.Analyzer.FindAlertsRuleConfig;
import Config.EvolutionaryFuzzerConfig;
import Graphs.BranchTrace;
import Result.Result;
import TestHelper.WorkFlowTraceFakeExecuter;
import TestVector.TestVector;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
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
public class FindAlertsRuleTest {

    private FindAlertsRule rule;

    public FindAlertsRuleTest() {
    }

    @Before
    public void setUp() {
	EvolutionaryFuzzerConfig config = new EvolutionaryFuzzerConfig();
	config.setOutputFolder("unit_test_output/");
	config.setConfigFolder("unit_test_config/");
	rule = new FindAlertsRule(config);
	rule.getConfig().setSaveOneOfEach(false);
    }

    @After
    public void tearDown() {
	FileHelper.deleteFolder(new File("unit_test_output"));
	FileHelper.deleteFolder(new File("unit_test_config"));
    }

    /**
     * Test of applys method, of class FindAlertsRule.
     */
    @Test
    public void testApplys() {
	WorkflowTrace trace = new WorkflowTrace();
	trace.add(new SendAction(new ClientHelloMessage()));
	trace.add(new SendAction(new HeartbeatMessage()));
	trace.add(new ReceiveAction(new HeartbeatMessage()));
	Result result = new Result(false, false, 1000, 2000, new BranchTrace(), new TestVector(trace, null, null,
		ExecutorType.TLS, null), "unittest.id");
	WorkFlowTraceFakeExecuter.execute(trace);
	assertFalse(rule.applys(result)); // Should not apply cause it has no
	// alert message
	AlertMessage message = new AlertMessage();
	message.setDescription((byte) 0xFE);
	trace.add(new SendAction(message));
	WorkFlowTraceFakeExecuter.execute(trace);
	assertFalse(rule.applys(result)); // Should not apply cause the alert
	// message is sent by the client
	message = new AlertMessage();
	message.setDescription((byte) 20);
	trace.add(new ReceiveAction(message));
	WorkFlowTraceFakeExecuter.execute(trace);
	assertFalse(rule.applys(result)); // Should not apply since the alert
	// Message is on the WhiteList
	message.setDescription((byte) 127);
	WorkFlowTraceFakeExecuter.execute(trace);
	assertTrue(rule.applys(result)); // Should apply since the description
	// // is not on the whitelist
	message.setDescription((byte) 60);

	assertTrue(rule.applys(result)); // Should apply since the description
	// is on the blacklist

    }

    /**
     * Test of onApply method, of class FindAlertsRule.
     */
    @Test
    public void testOnApply() {
	WorkflowTrace trace = new WorkflowTrace();
	trace.add(new SendAction(new ClientHelloMessage()));
	trace.add(new SendAction(new HeartbeatMessage()));
	trace.add(new ReceiveAction(new AlertMessage()));
	Result result = new Result(false, false, 1000, 2000, new BranchTrace(), new TestVector(trace, null, null,
		ExecutorType.TLS, null), "unittest.id");
	rule.onApply(result);
	assertTrue(new File("unit_test_output/" + rule.getConfig().getOutputFolder()).listFiles().length == 1);
    }

    @Test
    public void testOneOfEach() {
	rule.getConfig().setSaveOneOfEach(true);
	WorkflowTrace trace = new WorkflowTrace();
	trace.add(new SendAction(new ClientHelloMessage()));
	trace.add(new SendAction(new HeartbeatMessage()));
	Result result = new Result(false, false, 1000, 2000, new BranchTrace(), new TestVector(trace, null, null,
		ExecutorType.TLS, null), "unittest.id");
	AlertMessage message = new AlertMessage();
	message.setDescription((byte) 20);
	trace.add(new ReceiveAction(message));
	WorkFlowTraceFakeExecuter.execute(trace);

	assertTrue(rule.applys(result)); // Should apply since it is the first
	rule.onApply(result); // time the rule sees the alert code
	assertFalse(rule.applys(result)); // Should not apply since the rule has
	// already seen the alert code
    }

    /**
     * Test of onDecline method, of class FindAlertsRule.
     */
    @Test
    public void testOnDecline() {
	rule.onDecline(null);
    }

    /**
     * Test of report method, of class FindAlertsRule.
     */
    @Test
    public void testReport() {
	rule.onApply(new Result(true, true, 9, 10, new BranchTrace(), new TestVector(new WorkflowTrace(), null, null,
		ExecutorType.TLS, null), "2unit.test"));
	assertNotNull(rule.report());
    }

    /**
     * Test of getConfig method, of class FindAlertsRule.
     */
    @Test
    public void testGetConfig() {
	assertNotNull(rule.getConfig());
    }

}
