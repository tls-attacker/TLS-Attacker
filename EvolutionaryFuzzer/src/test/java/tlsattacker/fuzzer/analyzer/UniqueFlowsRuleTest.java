/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer;

import tlsattacker.fuzzer.analyzer.rules.UniqueFlowsRule;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.graphs.BranchTrace;
import tlsattacker.fuzzer.result.AgentResult;
import tlsattacker.fuzzer.testhelper.WorkFlowTraceFakeExecuter;
import tlsattacker.fuzzer.testvector.TestVector;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
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
public class UniqueFlowsRuleTest {

    /**
     *
     */
    private UniqueFlowsRule rule;

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private EvolutionaryFuzzerConfig config;

    /**
     *
     */
    public UniqueFlowsRuleTest() {
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
        rule = new UniqueFlowsRule(config);
    }

    /**
     * Test of applies method, of class UniqueFlowsRule.
     */
    @Test
    public void testApplys() {
        WorkflowTrace trace = new WorkflowTrace();
        trace.add(new SendAction(new CertificateRequestMessage()));
        AgentResult result = new AgentResult(false, false, 0, 1, new BranchTrace(), new TestVector(trace, null, null,
                ExecutorType.TLS, null), "tes2t.unit", null);
        WorkFlowTraceFakeExecuter.execute(trace);
        assertTrue(rule.applies(result));// Should apply since its the first
        // time
        // the rule has seen this tracetype
        assertTrue(rule.applies(result));// Should not apply since its the
        // second
        // time the rule has seen this
        // tracetype

    }

    /**
     * Test of onApply method, of class UniqueFlowsRule.
     */
    @Test
    public void testOnApply() {
        WorkflowTrace trace = new WorkflowTrace();
        trace.add(new SendAction(new CertificateRequestMessage()));
        AgentResult result = new AgentResult(false, false, 0, 1, new BranchTrace(), new TestVector(trace, null, null,
                ExecutorType.TLS, null), "tes2t.unit", null);
        rule.onApply(result);
        WorkFlowTraceFakeExecuter.execute(trace);
        assertTrue(new File(config.getOutputFolder() + rule.getConfig().getOutputFolder()).listFiles().length == 1);

    }

    /**
     * Test of onDecline method, of class UniqueFlowsRule.
     */
    @Test
    public void testOnDecline() {
        rule.onDecline(null);
    }

    /**
     * Test of report method, of class UniqueFlowsRule.
     */
    @Test
    public void testReport() {
        WorkflowTrace trace = new WorkflowTrace();
        ClientHelloMessage clientHello = new ClientHelloMessage();
        trace.add(new SendAction(clientHello));
        ServerHelloMessage serverHello = new ServerHelloMessage();
        trace.add(new ReceiveAction(serverHello));
        AgentResult result = new AgentResult(false, false, 0, 1, new BranchTrace(), new TestVector(trace, null, null,
                ExecutorType.TLS, null), "tes2t.unit", null);
        WorkFlowTraceFakeExecuter.execute(trace);
        rule.onApply(result);
        assertNotNull(rule.report());
    }

    /**
     * Test of getConfig method, of class UniqueFlowsRule.
     */
    @Test
    public void testGetConfig() {
        assertNotNull(rule.getConfig());
    }

}
