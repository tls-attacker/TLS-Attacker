/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.helper;

import de.rub.nds.tlsattacker.dtls.protocol.handshake.ClientHelloDtlsMessage;
import de.rub.nds.tlsattacker.dtls.protocol.handshake.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.modifiablevariable.util.ModifiableVariableField;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.application.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.HelloRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeCipherSuiteAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeClientCertificateAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeClientRandomAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeCompressionAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeMasterSecretAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangePreMasterSecretAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeProtocolVersionAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeServerCertificateAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeServerRandomAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ToggleEncryptionAction;
import de.rub.nds.tlsattacker.util.BadRandom;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.logging.Logger;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;
import tlsattacker.fuzzer.modification.AddExtensionModification;
import tlsattacker.fuzzer.modification.Modification;
import tlsattacker.fuzzer.mutator.certificate.FixedCertificateMutator;
import tlsattacker.fuzzer.testhelper.MockedRandom;
import tlsattacker.fuzzer.testhelper.UnitTestCertificateMutator;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class FuzzingHelperTest {

    private FuzzingHelper fuzzingHelper;
    private MockedRandom random;

    /**
     *
     */
    public FuzzingHelperTest() {
    }

    @Before
    public void setUp() {
        fuzzingHelper = new FuzzingHelper();
        random = new MockedRandom();
        fuzzingHelper.setRandom(random);
    }

    /**
     * Test of pickRandomField method, of class FuzzingHelper.
     */
    @Test
    public void testPickRandomField() {
        List<ModifiableVariableField> fields = new ArrayList<>();
        fields.add(new ModifiableVariableField());
        fields.add(new ModifiableVariableField());
        fields.add(new ModifiableVariableField());
        random.addNumber(0);
        random.addNumber(1);
        random.addNumber(2);
        random.addNumber(200);
        ModifiableVariableField result = fuzzingHelper.pickRandomField(fields);
        assertNotNull("Failure: Should return a Field", result);
        result = fuzzingHelper.pickRandomField(fields);
        assertNotNull("Failure: Should return a Field", result);
        result = fuzzingHelper.pickRandomField(fields);
        assertNotNull("Failure: Should return a Field", result);
        result = fuzzingHelper.pickRandomField(fields);
        assertNotNull("Failure: Should return a Field", result);
    }

    /**
     * Test of getModifiableVariableHolders method, of class FuzzingHelper.
     */
    @Test
    public void testGetModifiableVariableHolders() {
        WorkflowTrace trace = new WorkflowTrace();
        trace.add(new SendAction(new ClientHelloMessage()));
        List<ModifiableVariableHolder> result = fuzzingHelper.getModifiableVariableHolders(trace);
        assertTrue("Failure: WorkflowTrace should contain one Holder", result.size() == 1);
        result = fuzzingHelper.getModifiableVariableHolders(new WorkflowTrace());
        assertTrue("Failure: WorkflowTrace should contain no Holders", result.size() == 0);

    }

    /**
     * Test of addRecordAtRandom method, of class FuzzingHelper.
     */
    @Test
    public void testAddRecordsAtRandom() {
        WorkflowTrace trace = new WorkflowTrace();
        trace.add(new SendAction(new ClientHelloMessage()));
        random.addNumber(0);
        random.addNumber(1);
        random.addNumber(1);
        fuzzingHelper.addRecordAtRandom(trace);
        assertTrue(trace.getFirstConfiguredSendMessageOfType(HandshakeMessageType.CLIENT_HELLO).getRecords().size() == 1);
        random.addNumber(0);
        random.addNumber(50);
        random.addNumber(20000);
        fuzzingHelper.addRecordAtRandom(trace);
        assertTrue(trace.getFirstConfiguredSendMessageOfType(HandshakeMessageType.CLIENT_HELLO).getRecords().size() == 2);
        assertNull(fuzzingHelper.addRecordAtRandom(new WorkflowTrace()));

    }

    /**
     * Test of removeRandomMessage method, of class FuzzingHelper.
     */
    @Test
    public void testRemoveRandomMessage() {
        WorkflowTrace tempTrace = new WorkflowTrace();
        tempTrace.add(new SendAction(new ClientHelloMessage()));
        tempTrace.add(new ReceiveAction(new ServerHelloMessage()));
        fuzzingHelper.setRandom(new Random());
        fuzzingHelper.removeRandomMessage(tempTrace);
        assertTrue(
                "Failure: Workflow should contain only two Messages after. Since both Actions only contain one message",
                tempTrace.getAllConfiguredMessages().size() == 2);
        tempTrace = new WorkflowTrace();
        List<ProtocolMessage> messages = new LinkedList<>();
        messages.add(new AlertMessage());
        messages.add(new AlertMessage());
        tempTrace.add(new SendAction(messages));
        assertTrue("Failure: Workflow should contain two Messages", tempTrace.getAllConfiguredMessages().size() == 2);
        fuzzingHelper.removeRandomMessage(tempTrace);
        assertTrue("Failure: Workflow should contain only one Message after.", tempTrace.getAllConfiguredMessages()
                .size() == 1);

    }

    /**
     * Test of addRandomMessage method, of class FuzzingHelper.
     */
    @Test
    public void testAddRandomMessage() {
        WorkflowTrace tempTrace = new WorkflowTrace();
        tempTrace.add(new SendAction());
        fuzzingHelper.setRandom(new Random());

        assertTrue(fuzzingHelper.addRandomMessage(tempTrace) != null);
        assertTrue(
                "A Workflowtrace should contain 3 Messages after we added one at Random. (The arbitary Message for the Server is always added + random message from flight)",
                tempTrace.getAllConfiguredMessages().size() == 1);
        assertNull(fuzzingHelper.addRandomMessage(new WorkflowTrace()));
    }

    @Test
    public void testAddExtensionMessage() {
        WorkflowTrace trace = new WorkflowTrace();
        ClientHelloMessage message = new ClientHelloMessage();
        trace.add(new SendAction(message));
        fuzzingHelper.setRandom(new Random());
        Modification modification = fuzzingHelper.addExtensionMessage(trace);
        assertEquals(modification.getClass(), AddExtensionModification.class);
        assertTrue(message.getExtensions().size() == 1);
        trace = new WorkflowTrace();
        message = new ClientHelloDtlsMessage();
        trace.add(new SendAction(message));
        modification = fuzzingHelper.addExtensionMessage(trace);
        assertEquals(modification.getClass(), AddExtensionModification.class);
        assertTrue(message.getExtensions().size() == 1);

    }

    /**
     * Test of duplicateRandomProtocolMessage method, of class FuzzingHelper.
     */
    @Test
    public void testDuplicateRandomProtocolMessage() {
        WorkflowTrace trace = new WorkflowTrace();
        fuzzingHelper.setRandom(new Random());
        assertNull(fuzzingHelper.duplicateRandomProtocolMessage(trace));
        trace.add(new SendAction(new ClientHelloMessage()));
        fuzzingHelper.duplicateRandomProtocolMessage(trace);
        assertTrue("Failure: After Duplicating the Trace should contain 2 Messages", trace.getAllConfiguredMessages()
                .size() == 2);

    }

    /**
     * Test of getAllModifiableVariableHoldersRecursively method, of class
     * FuzzingHelper.
     */
    @Test
    public void testGetAllModifiableVariableHoldersRecursively() {
        WorkflowTrace trace = new WorkflowTrace();
        trace.add(new SendAction(new ClientHelloMessage()));

        int size = fuzzingHelper.getAllModifiableVariableFieldsRecursively(trace).size();
        assertTrue("Failure: Trace should contain more than zero Holders", size > 0);
    }

    @Test
    public void testGetRandom() {
        assertNotNull(new FuzzingHelper().getRandom());
    }

    @Test
    public void testSetRandom() {
        Random r = new BadRandom();
        fuzzingHelper.setRandom(r);
        assertEquals(fuzzingHelper.getRandom(), r);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSetRandomNull() {
        fuzzingHelper.setRandom(null);
    }

    @Test
    public void testAddToggleEncryptionAction() {
        fuzzingHelper.setRandom(new Random());
        WorkflowTrace trace = new WorkflowTrace();
        fuzzingHelper.addToggleEncrytionActionModification(trace);
        assertTrue(trace.getTLSActions().size() == 1);
        assertTrue(trace.getTLSActions().get(0) instanceof ToggleEncryptionAction);
    }

    @Test
    public void testGenerateRandomMessage() {
        random.addNumber(0);
        ProtocolMessage message = fuzzingHelper.generateRandomMessage();
        assertEquals(message.getClass(), AlertMessage.class);
        random.addNumber(1);
        message = fuzzingHelper.generateRandomMessage();
        assertEquals(message.getClass(), ApplicationMessage.class);
        random.addNumber(2);
        message = fuzzingHelper.generateRandomMessage();
        assertEquals(message.getClass(), CertificateMessage.class);
        random.addNumber(3);
        message = fuzzingHelper.generateRandomMessage();
        assertEquals(message.getClass(), CertificateRequestMessage.class);
        random.addNumber(4);
        message = fuzzingHelper.generateRandomMessage();
        assertEquals(message.getClass(), CertificateVerifyMessage.class);
        random.addNumber(5);
        message = fuzzingHelper.generateRandomMessage();
        assertEquals(message.getClass(), ChangeCipherSpecMessage.class);
        random.addNumber(6);
        random.addNumber(6);
        message = fuzzingHelper.generateRandomMessage();
        assertEquals(message.getClass(), ClientHelloDtlsMessage.class);
        random.addNumber(7);
        random.addNumber(7);
        message = fuzzingHelper.generateRandomMessage();
        assertEquals(message.getClass(), ClientHelloMessage.class);
        random.addNumber(8);
        message = fuzzingHelper.generateRandomMessage();
        assertEquals(message.getClass(), DHClientKeyExchangeMessage.class);
        random.addNumber(9);
        message = fuzzingHelper.generateRandomMessage();
        assertEquals(message.getClass(), HelloVerifyRequestMessage.class);
        random.addNumber(10);
        message = fuzzingHelper.generateRandomMessage();
        assertEquals(message.getClass(), DHEServerKeyExchangeMessage.class);
        random.addNumber(11);
        message = fuzzingHelper.generateRandomMessage();
        assertEquals(message.getClass(), ECDHClientKeyExchangeMessage.class);
        random.addNumber(12);
        message = fuzzingHelper.generateRandomMessage();
        assertEquals(message.getClass(), ECDHEServerKeyExchangeMessage.class);
        random.addNumber(13);
        message = fuzzingHelper.generateRandomMessage();
        assertEquals(message.getClass(), FinishedMessage.class);
        random.addNumber(14);
        message = fuzzingHelper.generateRandomMessage();
        assertEquals(message.getClass(), HeartbeatMessage.class);
        random.addNumber(15);
        message = fuzzingHelper.generateRandomMessage();
        assertEquals(message.getClass(), RSAClientKeyExchangeMessage.class);
        random.addNumber(16);
        message = fuzzingHelper.generateRandomMessage();
        assertEquals(message.getClass(), ServerHelloDoneMessage.class);
        random.addNumber(17);
        message = fuzzingHelper.generateRandomMessage();
        assertEquals(message.getClass(), HelloRequestMessage.class);
    }

    @Test
    public void testAddContextAction() {
        WorkflowTrace trace = new WorkflowTrace();
        random.addNumber(0);
        random.addNumber(0);
        fuzzingHelper.addContextAction(trace, new UnitTestCertificateMutator());
        assertEquals(trace.getTLSActions().get(0).getClass(), ChangeCipherSuiteAction.class);
        trace = new WorkflowTrace();
        random.addNumber(1);
        random.addNumber(0);
        fuzzingHelper.addContextAction(trace, new UnitTestCertificateMutator());
        assertEquals(trace.getTLSActions().get(0).getClass(), ChangeClientCertificateAction.class);
        trace = new WorkflowTrace();
        random.addNumber(0);
        random.addNumber(2);
        random.addNumber(0);
        fuzzingHelper.addContextAction(trace, new UnitTestCertificateMutator());
        assertEquals(trace.getTLSActions().get(0).getClass(), ChangeClientRandomAction.class);
        trace = new WorkflowTrace();
        random.addNumber(3);
        random.addNumber(0);
        fuzzingHelper.addContextAction(trace, new UnitTestCertificateMutator());
        assertEquals(trace.getTLSActions().get(0).getClass(), ChangeCompressionAction.class);
        trace = new WorkflowTrace();
        random.addNumber(0);
        random.addNumber(4);
        random.addNumber(0);
        fuzzingHelper.addContextAction(trace, new UnitTestCertificateMutator());
        assertEquals(trace.getTLSActions().get(0).getClass(), ChangeMasterSecretAction.class);
        trace = new WorkflowTrace();
        random.addNumber(0);
        random.addNumber(5);
        random.addNumber(0);
        fuzzingHelper.addContextAction(trace, new UnitTestCertificateMutator());
        assertEquals(trace.getTLSActions().get(0).getClass(), ChangePreMasterSecretAction.class);
        trace = new WorkflowTrace();
        random.addNumber(6);
        random.addNumber(0);
        fuzzingHelper.addContextAction(trace, new UnitTestCertificateMutator());
        assertEquals(trace.getTLSActions().get(0).getClass(), ChangeProtocolVersionAction.class);
        trace = new WorkflowTrace();
        random.addNumber(7);
        random.addNumber(0);
        fuzzingHelper.addContextAction(trace, new UnitTestCertificateMutator());
        assertEquals(trace.getTLSActions().get(0).getClass(), ChangeServerCertificateAction.class);
        trace = new WorkflowTrace();
        random.addNumber(0);
        random.addNumber(8);
        random.addNumber(0);
        fuzzingHelper.addContextAction(trace, new UnitTestCertificateMutator());
        assertEquals(trace.getTLSActions().get(0).getClass(), ChangeServerRandomAction.class);
    }

    @Test
    public void testAddMessageFlight() {
        fuzzingHelper.setRandom(new Random());
        WorkflowTrace trace = new WorkflowTrace();
        fuzzingHelper.addMessageFlight(trace);
        assertTrue(trace.getTLSActions().size() == 2);
        assertTrue(trace.getTLSActions().get(0) instanceof SendAction);
        assertTrue(trace.getTLSActions().get(1) instanceof ReceiveAction);
    }

    @Test
    public void testExecuteModifiabeVariableModification() {
        WorkflowTrace trace = new WorkflowTrace();
        trace.add(new SendAction(new ClientHelloMessage()));
        List<ModifiableVariableField> variableList = fuzzingHelper.getAllModifiableVariableFieldsRecursively(trace);
        ModifiableVariableField field = variableList.get(0);
        fuzzingHelper.executeModifiableVariableModification((ModifiableVariableHolder) (field.getObject()),
                field.getField());
    }

    private static final Logger LOG = Logger.getLogger(FuzzingHelperTest.class.getName());

}
