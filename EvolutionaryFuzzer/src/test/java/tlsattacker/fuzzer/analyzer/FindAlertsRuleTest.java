/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer;

import tlsattacker.fuzzer.analyzer.rules.FindAlertsRule;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.graphs.BranchTrace;
import tlsattacker.fuzzer.result.AgentResult;
import tlsattacker.fuzzer.testhelper.WorkFlowTraceFakeExecuter;
import tlsattacker.fuzzer.testvector.TestVector;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
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
 * @author ic0ns
 */
public class FindAlertsRuleTest {

    /**
     *
     */
    private FindAlertsRule rule;

    
    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();
    
    private EvolutionaryFuzzerConfig config;
    
    /**
     *
     */
    public FindAlertsRuleTest() {
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
        rule = new FindAlertsRule(config);
        rule.getConfig().setSaveOneOfEach(false);
    }

    /**
     * Test of applies method, of class FindAlertsRule.
     */
    @Test
    public void testApplys() {
        WorkflowTrace trace = new WorkflowTrace();
        trace.add(new SendAction(new ClientHelloMessage()));
        trace.add(new SendAction(new HeartbeatMessage()));
        trace.add(new ReceiveAction(new HeartbeatMessage()));
        AgentResult result = new AgentResult(false, false, 1000, 2000, new BranchTrace(), new TestVector(trace, null, null,
                ExecutorType.TLS, null), "unittest.id", null);
        WorkFlowTraceFakeExecuter.execute(trace);
        assertFalse(rule.applies(result)); // Should not apply cause it has no
        // alert message
        AlertMessage message = new AlertMessage();
        message.setDescription((byte) 0xFE);
        trace.add(new SendAction(message));
        WorkFlowTraceFakeExecuter.execute(trace);
        assertFalse(rule.applies(result)); // Should not apply cause the alert
        // message is sent by the client
        message = new AlertMessage();
        message.setDescription((byte) 20);
        trace.add(new ReceiveAction(message));
        WorkFlowTraceFakeExecuter.execute(trace);
        assertFalse(rule.applies(result)); // Should not apply since the alert
        // Message is on the WhiteList
        message.setDescription((byte) 127);
        WorkFlowTraceFakeExecuter.execute(trace);
        assertTrue(rule.applies(result)); // Should apply since the description
        // // is not on the whitelist
        message.setDescription((byte) 60);

        assertTrue(rule.applies(result)); // Should apply since the description
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
        AgentResult result = new AgentResult(false, false, 1000, 2000, new BranchTrace(), new TestVector(trace, null, null,
                ExecutorType.TLS, null), "unittest.id", null);
        rule.onApply(result);
        assertTrue(new File(config.getOutputFolder() + rule.getConfig().getOutputFolder()).listFiles().length == 1);
    }

    /**
     *
     */
    @Test
    public void testOneOfEach() {
        rule.getConfig().setSaveOneOfEach(true);
        WorkflowTrace trace = new WorkflowTrace();
        trace.add(new SendAction(new ClientHelloMessage()));
        trace.add(new SendAction(new HeartbeatMessage()));
        AgentResult result = new AgentResult(false, false, 1000, 2000, new BranchTrace(), new TestVector(trace, null, null,
                ExecutorType.TLS, null), "unittest.id", null);
        AlertMessage message = new AlertMessage();
        message.setDescription((byte) 20);
        trace.add(new ReceiveAction(message));
        WorkFlowTraceFakeExecuter.execute(trace);

        assertTrue(rule.applies(result)); // Should apply since it is the first
        rule.onApply(result); // time the rule sees the alert code
        assertFalse(rule.applies(result)); // Should not apply since the rule
        // has
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
        rule.onApply(new AgentResult(true, true, 9, 10, new BranchTrace(), new TestVector(new WorkflowTrace(), null, null,
                ExecutorType.TLS, null), "2unit.test", null));
        assertNotNull(rule.report());
    }

    /**
     * Test of getConfig method, of class FindAlertsRule.
     */
    @Test
    public void testGetConfig() {
        assertNotNull(rule.getConfig());
    }

    private static final Logger LOG = Logger.getLogger(FindAlertsRuleTest.class.getName());

}
