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
import TestVector.TestVector;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
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
	// TODO how to make sure the map is not initialized while tasting?

    }

    /**
     * Test of onApply method, of class FindAlertsRule.
     */
    @Test
    public void testOnApply() {
	WorkflowTrace trace = new WorkflowTrace();
	trace.add(new ClientHelloMessage(ConnectionEnd.CLIENT));
	trace.add(new HeartbeatMessage(ConnectionEnd.CLIENT));
	trace.add(new HeartbeatMessage(ConnectionEnd.SERVER));
	Result result = new Result(false, false, 1000, 2000, new BranchTrace(),
		new TestVector(trace, null, null, null), new TestVector(trace, null, null, null), "unittest.id");
	assertFalse(rule.applys(result)); // Should not apply cause it has no
					  // alert message
	AlertMessage message = new AlertMessage(ConnectionEnd.CLIENT);
	message.setDescription((byte) 0xFE);
	trace.add(message);
	assertFalse(rule.applys(result)); // Should not apply cause the alert
					  // message is sent by the client
	message = new AlertMessage(ConnectionEnd.SERVER);
	message.setDescription((byte) 20);
	trace.add(message);
	assertFalse(rule.applys(result)); // Should not apply since the alert
					  // Message is on the WhiteList
	message.setDescription((byte) 127);
	assertTrue(rule.applys(result)); // Should apply since the description
					 // // is not on the whitelist
	message.setDescription((byte) 60);
	assertTrue(rule.applys(result)); // Should apply since the description
					 // is on the blacklist
    }

    @Test
    public void testOneOfEach() {
	rule.getConfig().setSaveOneOfEach(true);
	WorkflowTrace trace = new WorkflowTrace();
	trace.add(new ClientHelloMessage(ConnectionEnd.CLIENT));
	trace.add(new HeartbeatMessage(ConnectionEnd.CLIENT));
	Result result = new Result(false, false, 1000, 2000, new BranchTrace(),
		new TestVector(trace, null, null, null), new TestVector(trace, null, null, null), "unittest.id");
	AlertMessage message = new AlertMessage(ConnectionEnd.SERVER);
	message.setDescription((byte) 20);
	trace.add(message);
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
		null), new TestVector(new WorkflowTrace(), null, null, null), "unit.test"));
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
