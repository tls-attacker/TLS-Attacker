/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.analyzer;

import tlsattacker.fuzzer.analyzer.helpers.ModificationCounter;
import tlsattacker.fuzzer.analyzer.rules.AnalyzeGoodModificationRule;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.graphs.BranchTrace;
import tlsattacker.fuzzer.modification.AddMessageModification;
import tlsattacker.fuzzer.modification.AddRecordModification;
import tlsattacker.fuzzer.modification.ChangeServerCertificateModification;
import tlsattacker.fuzzer.modification.DuplicateMessageModification;
import tlsattacker.fuzzer.modification.ModifyFieldModification;
import tlsattacker.fuzzer.result.AgentResult;
import tlsattacker.fuzzer.testvector.TestVector;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import java.io.IOException;
import java.util.List;
import java.util.logging.Logger;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AnalyzeGoodModificationRuleTest {

    /**
     *
     */
    private AnalyzeGoodModificationRule rule;

    /**
     *
     */
    private TestVector vector;

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();
    
    /**
     *
     */
    public AnalyzeGoodModificationRuleTest() {
    }

    /**
     *
     */
    @Before
    public void setUp() throws IOException {
        EvolutionaryFuzzerConfig config = new EvolutionaryFuzzerConfig();
        config.setOutputFolder(tempFolder.newFolder().getAbsolutePath());
        config.setConfigFolder(tempFolder.newFolder().getAbsolutePath());
        config.createFolders();
        rule = new AnalyzeGoodModificationRule(config);
        vector = new TestVector(null, null, null, ExecutorType.TLS, null);
        vector.addModification(new AddMessageModification(new ClientHelloMessage(), new SendAction()));
        vector.addModification(new AddRecordModification(new ClientHelloMessage()));
        vector.addModification(new ChangeServerCertificateModification(null));
        vector.addModification(new DuplicateMessageModification(new ClientHelloMessage(), new SendAction(), 0));
        vector.addModification(new ModifyFieldModification("test", new AlertMessage()));

    }

    /**
     * Test of applies method, of class AnalyzeModificationRule.
     */
    @Test
    public void testApplys() {
        AgentResult result = new AgentResult(false, false, 1000, 2000, new BranchTrace(), new TestVector(), "unittest.id", null);

        assertFalse(rule.applies(result));
        result.setGoodTrace(true);
        assertTrue(rule.applies(result));

    }

    /**
     * Test of onApply method, of class AnalyzeModificationRule.
     */
    @Test
    public void testOnApply() {
        AgentResult result = new AgentResult(false, false, 1000, 2000, new BranchTrace(), vector, "unittest.id", null);
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
        AgentResult result = new AgentResult(false, false, 1000, 2000, new BranchTrace(), vector, "unittest.id", null);
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
        AgentResult result = new AgentResult(false, false, 1000, 2000, new BranchTrace(), vector, "unittest.id", null);
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
        AgentResult result = new AgentResult(false, false, 1000, 2000, new BranchTrace(), vector, "unittest.id", null);
        rule.onApply(result);
        vector.addModification(new AddMessageModification(new ServerHelloDoneMessage(), new SendAction()));
        rule.onApply(result);
        List<ModificationCounter> counterList = rule.getCounterList();
        ModificationCounter counter = counterList.get(1);
        assertTrue(counter.getCounter() == 2);
        counter = counterList.get(0);
        assertTrue(counter.getCounter() == 3);
    }

    private static final Logger LOG = Logger.getLogger(AnalyzeGoodModificationRuleTest.class.getName());
}
