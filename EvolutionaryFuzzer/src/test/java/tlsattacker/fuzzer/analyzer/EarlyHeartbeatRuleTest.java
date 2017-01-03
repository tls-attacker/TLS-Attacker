/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer;

import tlsattacker.fuzzer.analyzer.rules.EarlyHeartbeatRule;
import tlsattacker.fuzzer.testhelper.WorkFlowTraceFakeExecuter;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.graphs.BranchTrace;
import tlsattacker.fuzzer.result.AgentResult;
import tlsattacker.fuzzer.testvector.TestVector;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import java.io.File;
import java.io.IOException;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class EarlyHeartbeatRuleTest {

    /**
     *
     */
    private EarlyHeartbeatRule rule;

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private EvolutionaryFuzzerConfig config;

    /**
     *
     */
    public EarlyHeartbeatRuleTest() {

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
        rule = new EarlyHeartbeatRule(config);
    }

    /**
     * Test of applies method, of class EarlyHeartbeatRule.
     */
    @Test
    public void testApplys() {
        WorkflowTrace trace = new WorkflowTrace();
        trace.add(new SendAction(new ClientHelloMessage()));
        trace.add(new SendAction(new HeartbeatMessage()));
        trace.add(new ReceiveAction(new HeartbeatMessage()));
        AgentResult result = new AgentResult(false, false, 1000, 2000, new BranchTrace(), new TestVector(trace, null,
                null, ExecutorType.TLS, null), "unittest.id", null);
        WorkFlowTraceFakeExecuter.execute(trace);
        assertTrue(rule.applies(result));
        trace.add(new ReceiveAction(new FinishedMessage()));
        WorkFlowTraceFakeExecuter.execute(trace);
        assertTrue(rule.applies(result));
        trace = new WorkflowTrace();
        trace.add(new SendAction(new ClientHelloMessage()));
        trace.add(new ReceiveAction(new FinishedMessage()));
        trace.add(new ReceiveAction(new HeartbeatMessage()));
        result = new AgentResult(false, false, 1000, 2000, new BranchTrace(), new TestVector(trace, null, null,
                ExecutorType.TLS, null), "unittest.id", null);
        WorkFlowTraceFakeExecuter.execute(trace);
        assertFalse(rule.applies(result));
        trace = new WorkflowTrace();
        trace.add(new SendAction(new ClientHelloMessage()));
        trace.add(new ReceiveAction(new FinishedMessage()));
        result = new AgentResult(false, false, 1000, 2000, new BranchTrace(), new TestVector(trace, null, null,
                ExecutorType.TLS, null), "unittest.id", null);
        WorkFlowTraceFakeExecuter.execute(trace);
        assertFalse(rule.applies(result));
        result = new AgentResult(false, false, 1000, 2000, new BranchTrace(), new TestVector(trace, null, null,
                ExecutorType.TLS, null), "unittest.id", null);
        trace = new WorkflowTrace();
        trace.add(new SendAction(new ClientHelloMessage()));
        trace.add(new ReceiveAction(new ServerHelloMessage()));
        WorkFlowTraceFakeExecuter.execute(trace);
        assertFalse(rule.applies(result));
    }

    /**
     * Test of onApply method, of class EarlyHeartbeatRule.
     */
    @Test
    public void testOnApply() {
        WorkflowTrace trace = new WorkflowTrace();
        trace.add(new SendAction(new ClientHelloMessage()));
        trace.add(new ReceiveAction(new HeartbeatMessage()));
        trace.add(new ReceiveAction(new HeartbeatMessage()));
        AgentResult result = new AgentResult(false, false, 1000, 2000, new BranchTrace(), new TestVector(trace, null,
                null, ExecutorType.TLS, null), "unittest.id", null);
        WorkFlowTraceFakeExecuter.execute(trace);
        rule.onApply(result);
        assertTrue(new File(config.getOutputFolder() + rule.getConfig().getOutputFolder()).listFiles().length == 1);

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
        trace.add(new SendAction(new ClientHelloMessage()));
        trace.add(new SendAction(new HeartbeatMessage()));
        trace.add(new ReceiveAction(new HeartbeatMessage()));
        WorkFlowTraceFakeExecuter.execute(trace);
        AgentResult result = new AgentResult(false, false, 1000, 2000, new BranchTrace(), new TestVector(trace, null,
                null, ExecutorType.TLS, null), "unittest.id", null);
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
