/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Analyzer;

import Config.Analyzer.UniqueFlowsRuleConfig;
import Config.EvolutionaryFuzzerConfig;
import Graphs.BranchTrace;
import Result.Result;
import TestHelper.WorkFlowTraceFakeExecuter;
import TestVector.TestVector;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
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
 * @author Robert Merget - robert.merget@rub.de
 */
public class UniqueFlowsRuleTest {
    private UniqueFlowsRule rule;

    public UniqueFlowsRuleTest() {
    }

    @Before
    public void setUp() {
	EvolutionaryFuzzerConfig config = new EvolutionaryFuzzerConfig();
	config.setOutputFolder("unit_test_output/");
	config.setConfigFolder("unit_test_config/");
	rule = new UniqueFlowsRule(config);
    }

    @After
    public void tearDown() {
	FileHelper.deleteFolder(new File("unit_test_output"));
	FileHelper.deleteFolder(new File("unit_test_config"));
    }

    /**
     * Test of applys method, of class UniqueFlowsRule.
     */
    @Test
    public void testApplys() {
	WorkflowTrace trace = new WorkflowTrace();
	trace.add(new SendAction(new CertificateRequestMessage()));
	Result result = new Result(false, false, 0, 1, new BranchTrace(), new TestVector(trace, null, null,
		ExecutorType.TLS, null), "tes2t.unit");
	WorkFlowTraceFakeExecuter.execute(trace);
	assertTrue(rule.applys(result));// Should apply since its the first time
					// the rule has seen this tracetype
	assertTrue(rule.applys(result));// Should not apply since its the second
					// time the rule has seen this tracetype

    }

    /**
     * Test of onApply method, of class UniqueFlowsRule.
     */
    @Test
    public void testOnApply() {
	WorkflowTrace trace = new WorkflowTrace();
	trace.add(new SendAction(new CertificateRequestMessage()));
	Result result = new Result(false, false, 0, 1, new BranchTrace(), new TestVector(trace, null, null,
		ExecutorType.TLS, null), "tes2t.unit");
	rule.onApply(result);
	WorkFlowTraceFakeExecuter.execute(trace);
	assertTrue(new File("unit_test_output/" + rule.getConfig().getOutputFolder()).listFiles().length == 1);

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
	Result result = new Result(false, false, 0, 1, new BranchTrace(), new TestVector(trace, null, null,
		ExecutorType.TLS, null), "tes2t.unit");
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
