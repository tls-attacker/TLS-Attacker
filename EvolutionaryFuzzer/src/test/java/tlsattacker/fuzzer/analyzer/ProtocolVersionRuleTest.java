/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer;

import tlsattacker.fuzzer.analyzer.ProtocolVersionRule;
import tlsattacker.fuzzer.config.analyzer.ProtocolVersionRuleConfig;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.graphs.BranchTrace;
import tlsattacker.fuzzer.result.Result;
import tlsattacker.fuzzer.testhelper.WorkFlowTraceFakeExecuter;
import tlsattacker.fuzzer.testvector.TestVector;
import de.rub.nds.tlsattacker.eap.ClientHello;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
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
public class ProtocolVersionRuleTest {
    private ProtocolVersionRule rule;

    public ProtocolVersionRuleTest() {
    }

    @Before
    public void setUp() {
	EvolutionaryFuzzerConfig config = new EvolutionaryFuzzerConfig();
	config.setOutputFolder("unit_test_output/");
	config.setConfigFolder("unit_test_config/");
	rule = new ProtocolVersionRule(config);
    }

    @After
    public void tearDown() {
	FileHelper.deleteFolder(new File("unit_test_output/"));
	FileHelper.deleteFolder(new File("unit_test_config/"));
    }

    /**
     * Test of applys method, of class ProtocolVersionRule.
     */
    @Test
    public void testApplys() {
	WorkflowTrace trace = new WorkflowTrace();
	ClientHelloMessage clientHello = new ClientHelloMessage();
	clientHello.setProtocolVersion(ProtocolVersion.TLS12.getValue());
	trace.add(new SendAction(clientHello));
	Result result = new Result(false, false, 0, 1, new BranchTrace(), new TestVector(trace, null, null,
		ExecutorType.TLS, null), "test.unit");
	WorkFlowTraceFakeExecuter.execute(trace);
	assertFalse(rule.applys(result));
	ServerHelloMessage serverHello = new ServerHelloMessage();
	trace.add(new ReceiveAction(serverHello));
	serverHello.setProtocolVersion(ProtocolVersion.TLS12.getValue());
	WorkFlowTraceFakeExecuter.execute(trace);
	assertFalse(rule.applys(result));
	serverHello.setProtocolVersion(ProtocolVersion.TLS11.getValue());
	assertTrue(rule.applys(result)); // This is not the highest support
					 // version
	clientHello.setProtocolVersion(ProtocolVersion.TLS11.getValue());
	assertFalse(rule.applys(result)); // This should not apply, since the
					  // client
					  // also only support tls1.1
	clientHello.setProtocolVersion(ProtocolVersion.SSL2.getValue());
	serverHello.setProtocolVersion(ProtocolVersion.SSL2.getValue());
	assertTrue(rule.applys(result)); // This should appyl since SSL2 is on
					 // the blacklist and should never be
					 // negotiated
	serverHello.setProtocolVersion(new byte[] { 31, 24 });
	assertTrue(rule.applys(result)); // This should apply, since the
					 // ServerVersion is not standart
	clientHello.setProtocolVersion(new byte[] { 22, 34 });
	assertTrue(rule.applys(result)); // This should apply, since the
					 // ServerVersion is not standart
	serverHello.setProtocolVersion(ProtocolVersion.TLS12.getValue());
	clientHello.setProtocolVersion(new byte[] { 4 });
	assertTrue(rule.applys(result)); // This should apply, since the client
					 // field size is too short
	clientHello.setProtocolVersion(ProtocolVersion.TLS12.getValue());
	serverHello.setProtocolVersion(new byte[] { 4 });
	assertTrue(rule.applys(result)); // This should apply, since the client
					 // field size is too short
	serverHello.setProtocolVersion(ProtocolVersion.TLS12.getValue());
	clientHello.setProtocolVersion(ProtocolVersion.DTLS12.getValue());
	assertTrue(rule.applys(result)); // TLS DTLS MISMATCH
	assertTrue(rule.applys(result)); // This should apply, since the client
					 // field size is too short
	serverHello.setProtocolVersion(ProtocolVersion.DTLS12.getValue());
	clientHello.setProtocolVersion(ProtocolVersion.TLS12.getValue());
	assertTrue(rule.applys(result)); // TLS DTLS MISMATCH

    }

    /**
     * Test of onApply method, of class ProtocolVersionRule.
     */
    @Test
    public void testOnApply() {
	WorkflowTrace trace = new WorkflowTrace();
	ClientHelloMessage clientHello = new ClientHelloMessage();
	clientHello.setProtocolVersion(ProtocolVersion.TLS12.getValue());
	trace.add(new SendAction(clientHello));
	ServerHelloMessage serverHello = new ServerHelloMessage();
	trace.add(new ReceiveAction(serverHello));
	serverHello.setProtocolVersion(ProtocolVersion.SSL2.getValue());
	Result result = new Result(false, false, 0, 1, new BranchTrace(), new TestVector(trace, null, null,
		ExecutorType.TLS, null), "test.unit");
	WorkFlowTraceFakeExecuter.execute(trace);
	rule.onApply(result);
	assertTrue(new File("unit_test_output/" + rule.getConfig().getOutputFolder()).listFiles().length == 1);

    }

    /**
     * Test of onDecline method, of class ProtocolVersionRule.
     */
    @Test
    public void testOnDecline() {
	rule.onDecline(null);
    }

    /**
     * Test of report method, of class ProtocolVersionRule.
     */
    @Test
    public void testReport() {
	assertNull(rule.report());
	WorkflowTrace trace = new WorkflowTrace();
	ClientHelloMessage clientHello = new ClientHelloMessage();
	clientHello.setProtocolVersion(ProtocolVersion.TLS12.getValue());
	trace.add(new SendAction(clientHello));
	ServerHelloMessage serverHello = new ServerHelloMessage();
	trace.add(new ReceiveAction(serverHello));
	serverHello.setProtocolVersion(ProtocolVersion.SSL2.getValue());
	Result result = new Result(false, false, 0, 1, new BranchTrace(), new TestVector(trace, null, null,
		ExecutorType.TLS, null), "test.unit");
	WorkFlowTraceFakeExecuter.execute(trace);
	rule.onApply(result);
	assertNotNull(rule.report());
    }

    /**
     * Test of getConfig method, of class ProtocolVersionRule.
     */
    @Test
    public void testGetConfig() {
	assertNotNull(rule.getConfig());
    }

}
