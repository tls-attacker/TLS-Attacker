/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer;

import tlsattacker.fuzzer.analyzer.AnalyzeModificationRule;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.graphs.BranchTrace;
import tlsattacker.fuzzer.modification.AddMessageModification;
import tlsattacker.fuzzer.modification.AddRecordModification;
import tlsattacker.fuzzer.modification.ChangeServerCertificateModification;
import tlsattacker.fuzzer.modification.DuplicateMessageModification;
import tlsattacker.fuzzer.modification.ModificationType;
import tlsattacker.fuzzer.modification.ModifyFieldModification;
import tlsattacker.fuzzer.result.Result;
import tlsattacker.fuzzer.testvector.TestVector;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import de.rub.nds.tlsattacker.util.FileHelper;
import de.rub.nds.tlsattacker.wrapper.MutableInt;
import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author ic0ns
 */
public class AnalyzeModificationRuleTest {

    /**
     *
     */
    private AnalyzeModificationRule rule;

    /**
     *
     */
    private TestVector vector;

    /**
     *
     */
    public AnalyzeModificationRuleTest() {
    }

    /**
     *
     */
    @Before
    public void setUp() {
	EvolutionaryFuzzerConfig config = new EvolutionaryFuzzerConfig();
	config.setOutputFolder("unit_test_output/");
	config.setConfigFolder("unit_test_config/");
	rule = new AnalyzeModificationRule(config);
	vector = new TestVector(null, null, null, ExecutorType.TLS, null);
	vector.addModification(new AddMessageModification(new ClientHelloMessage(), new SendAction()));
	vector.addModification(new AddRecordModification(new ClientHelloMessage()));
	vector.addModification(new ChangeServerCertificateModification(null));
	vector.addModification(new DuplicateMessageModification(new ClientHelloMessage(), new SendAction(), 0));
	vector.addModification(new ModifyFieldModification("test", new AlertMessage()));

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
     * Test of applies method, of class AnalyzeModificationRule.
     */
    @Test
    public void testApplys() {
	Result result = new Result(false, false, 1000, 2000, new BranchTrace(), new TestVector(), "unittest.id");
	assertTrue(rule.applies(result));
    }

    /**
     * Test of onApply method, of class AnalyzeModificationRule.
     */
    @Test
    public void testOnApply() {
	Result result = new Result(false, false, 1000, 2000, new BranchTrace(), vector, "unittest.id");
	rule.onApply(result);
    }

    /**
     * Test of onDecline method, of class AnalyzeModificationRule.
     */
    @Test
    public void testOnDecline() {
	rule.onDecline(null);
    }

    /**
     * Test of report method, of class AnalyzeModificationRule.
     */
    @Test
    public void testReport() {
	Result result = new Result(false, false, 1000, 2000, new BranchTrace(), vector, "unittest.id");
	assertNull(rule.report());
	rule.onApply(result);
	assertNotNull(rule.report());
    }

    /**
     * Test of getConfig method, of class AnalyzeModificationRule.
     */
    @Test
    public void testGetConfig() {
	assertNotNull(rule.getConfig());
    }

    /**
     * Test of getExecutedTraces method, of class AnalyzeModificationRule.
     */
    @Test
    public void testGetExecutedTraces() {
	Result result = new Result(false, false, 1000, 2000, new BranchTrace(), vector, "unittest.id");
	rule.onApply(result);
	assertTrue(rule.getExecutedTraces() == 1);
	rule.onApply(result);
	assertTrue(rule.getExecutedTraces() == 2);

    }

    /**
     * Test of getTypeMap method, of class AnalyzeModificationRule.
     */
    @Test
    public void testGetTypeMap() {
	Result result = new Result(false, false, 1000, 2000, new BranchTrace(), vector, "unittest.id");
	rule.onApply(result);
	vector.addModification(new AddMessageModification(new ServerHelloDoneMessage(), new SendAction()));
	rule.onApply(result);
	List<ModificationCounter> counterList= rule.getCounterList();
	ModificationCounter counter = counterList.get(1);
	assertTrue(counter.getCounter() == 2);
	counter = counterList.get(0);
	assertTrue(counter.getCounter() == 3);
    }

    private static final Logger LOG = Logger.getLogger(AnalyzeModificationRuleTest.class.getName());
}
