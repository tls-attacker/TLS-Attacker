/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.unittest.helper.WorkFlowTraceFakeExecuter;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeCipherSuiteAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeClientCertificateAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeClientRandomAction;
import de.rub.nds.tlsattacker.core.workflow.action.ConfiguredReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TLSAction;
import java.util.LinkedList;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class WorkflowTraceTest {

    private WorkflowTrace trace;
    private TlsContext context;
    private Config config;

    @Before
    public void setUp() {
        trace = new WorkflowTrace();
        config = Config.createConfig();
        context = new TlsContext(config);
    }

    /**
     * Test of makeGeneric method, of class WorkflowTrace.
     */
    @Test
    public void testMakeGeneric() {
    }

    /**
     * Test of strip method, of class WorkflowTrace.
     */
    @Test
    public void testStrip() {
    }

    /**
     * Test of reset method, of class WorkflowTrace.
     */
    @Test
    public void testReset() {
    }

    /**
     * Test of getDescription method, of class WorkflowTrace.
     */
    @Test
    public void testGetDescription() {
        trace.setDescription("testDesc");
        assertEquals("testDesc", trace.getDescription());
    }

    /**
     * Test of setDescription method, of class WorkflowTrace.
     */
    @Test
    public void testSetDescription() {
        trace.setDescription("testDesc");
        assertEquals("testDesc", trace.getDescription());
    }

    /**
     * Test of add method, of class WorkflowTrace.
     */
    @Test
    public void testAdd_TLSAction() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        assertTrue(trace.getTlsActions().size() == 3);
        trace.addTlsAction(new ConfiguredReceiveAction());
        assertTrue(trace.getTlsActions().get(3).equals(new ConfiguredReceiveAction()));
    }

    /**
     * Test of add method, of class WorkflowTrace.
     */
    @Test
    public void testAdd_int_TLSAction() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        assertTrue(trace.getTlsActions().size() == 3);
        trace.addTlsAction(0, new ConfiguredReceiveAction());
        assertTrue(trace.getTlsActions().get(0).equals(new ConfiguredReceiveAction()));
    }

    /**
     * Test of remove method, of class WorkflowTrace.
     */
    @Test
    public void testRemove() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        assertTrue(trace.getTlsActions().size() == 3);
        trace.removeTlsAction(0);
        assertTrue(trace.getTlsActions().size() == 2);
    }

    /**
     * Test of getTlsActions method, of class WorkflowTrace.
     */
    @Test
    public void testGetTLSActions() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ConfiguredReceiveAction());
        assertTrue(trace.getTlsActions().size() == 2);
        assertEquals(trace.getTlsActions().get(0), new SendAction());
        assertEquals(trace.getTlsActions().get(1), new ConfiguredReceiveAction());
    }

    /**
     * Test of setTlsActions method, of class WorkflowTrace.
     */
    @Test
    public void testSetTlsActions() {
        LinkedList<TLSAction> actionList = new LinkedList<>();
        actionList.add(new SendAction());
        actionList.add(new ConfiguredReceiveAction());
        trace.setTlsActions(actionList);
        assertTrue(trace.getTlsActions().size() == 2);
        assertEquals(trace.getTlsActions().get(0), new SendAction());
        assertEquals(trace.getTlsActions().get(1), new ConfiguredReceiveAction());

    }

    /**
     * Test of getMessageActions method, of class WorkflowTrace.
     */
    @Test
    public void testGetMessageActions() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ConfiguredReceiveAction());
        trace.addTlsAction(new ChangeClientRandomAction());
        assertTrue(trace.getMessageActions().size() == 2);
        assertEquals(trace.getMessageActions().get(0), new SendAction());
        assertEquals(trace.getMessageActions().get(1), new ConfiguredReceiveAction());
    }

    /**
     * Test of getReceiveActions method, of class WorkflowTrace.
     */
    @Test
    public void testGetReceiveActions() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ConfiguredReceiveAction());
        trace.addTlsAction(new ChangeClientRandomAction());
        assertTrue(trace.getReceiveActions().size() == 1);
        assertEquals(trace.getReceiveActions().get(0), new ConfiguredReceiveAction());
    }

    /**
     * Test of getSendActions method, of class WorkflowTrace.
     */
    @Test
    public void testGetSendActions() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ConfiguredReceiveAction());
        trace.addTlsAction(new ChangeClientRandomAction());
        assertTrue(trace.getSendActions().size() == 1);
        assertEquals(trace.getSendActions().get(0), new SendAction());
    }

    /**
     * Test of getFirstConfiguredSendMessageOfType method, of class
     * WorkflowTrace.
     */
    @Test
    public void testGetFirstConfiguredSendMessageOfType_ProtocolMessageType() {
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new AlertMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        assertTrue(trace.getFirstConfiguredSendMessageOfType(ProtocolMessageType.ALERT) != null);
        assertTrue(trace.getFirstConfiguredSendMessageOfType(ProtocolMessageType.APPLICATION_DATA) == null);
    }

    /**
     * Test of getFirstConfiguredSendMessageOfType method, of class
     * WorkflowTrace.
     */
    @Test
    public void testGetFirstConfiguredSendMessageOfType_HandshakeMessageType() {
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new CertificateMessage()));
        trace.addTlsAction(new SendAction(new AlertMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        assertTrue(trace.getFirstConfiguredSendMessageOfType(HandshakeMessageType.CLIENT_HELLO) != null);
        assertTrue(trace.getFirstConfiguredSendMessageOfType(HandshakeMessageType.NEW_SESSION_TICKET) == null);

    }

    /**
     * Test of getFirstActuallySendMessageOfType method, of class WorkflowTrace.
     */
    @Test
    public void testGetFirstActuallySendMessageOfType_ProtocolMessageType() {
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new AlertMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        WorkFlowTraceFakeExecuter.execute(trace);
        assertTrue(trace.getFirstActuallySendMessageOfType(ProtocolMessageType.ALERT) != null);
        assertTrue(trace.getFirstActuallySendMessageOfType(ProtocolMessageType.APPLICATION_DATA) == null);
    }

    /**
     * Test of getFirstActuallySendMessageOfType method, of class WorkflowTrace.
     */
    @Test
    public void testGetFirstActuallySendMessageOfType_HandshakeMessageType() {
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new CertificateMessage()));
        trace.addTlsAction(new SendAction(new AlertMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        WorkFlowTraceFakeExecuter.execute(trace);
        assertTrue(trace.getFirstActuallySendMessageOfType(HandshakeMessageType.CLIENT_HELLO) != null);
        assertTrue(trace.getFirstActuallySendMessageOfType(HandshakeMessageType.NEW_SESSION_TICKET) == null);
    }

    /**
     * Test of getActualReceivedProtocolMessagesOfType method, of class
     * WorkflowTrace.
     */
    @Test
    public void testGetActualReceivedProtocolMessagesOfType() {
        trace.addTlsAction(new ConfiguredReceiveAction(new ClientHelloMessage()));
        trace.addTlsAction(new ConfiguredReceiveAction(new CertificateMessage()));
        trace.addTlsAction(new ConfiguredReceiveAction(new AlertMessage()));
        trace.addTlsAction(new ConfiguredReceiveAction(new ClientHelloMessage()));
        WorkFlowTraceFakeExecuter.execute(trace);
        assertTrue(trace.getActualReceivedProtocolMessagesOfType(ProtocolMessageType.ALERT).size() == 1);
        assertTrue(trace.getActualReceivedProtocolMessagesOfType(ProtocolMessageType.HANDSHAKE).size() == 3);
        assertTrue(trace.getActualReceivedProtocolMessagesOfType(ProtocolMessageType.APPLICATION_DATA).isEmpty());
    }

    /**
     * Test of getActuallyRecievedHandshakeMessagesOfType method, of class
     * WorkflowTrace.
     */
    @Test
    public void testGetActuallyRecievedHandshakeMessagesOfType() {
        trace.addTlsAction(new ConfiguredReceiveAction(new ClientHelloMessage()));
        trace.addTlsAction(new ConfiguredReceiveAction(new CertificateMessage()));
        trace.addTlsAction(new ConfiguredReceiveAction(new AlertMessage()));
        trace.addTlsAction(new ConfiguredReceiveAction(new ClientHelloMessage()));
        WorkFlowTraceFakeExecuter.execute(trace);
        assertTrue(trace.getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.CERTIFICATE).size() == 1);
        assertTrue(trace.getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.CLIENT_HELLO).size() == 2);
        assertTrue(trace.getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.HELLO_VERIFY_REQUEST)
                .isEmpty());
    }

    /**
     * Test of getActuallyRecievedProtocolMessagesOfType method, of class
     * WorkflowTrace.
     */
    @Test
    public void testGetActuallyRecievedProtocolMessagesOfType() {
        trace.addTlsAction(new ConfiguredReceiveAction(new ClientHelloMessage()));
        trace.addTlsAction(new ConfiguredReceiveAction(new CertificateMessage()));
        trace.addTlsAction(new ConfiguredReceiveAction(new AlertMessage()));
        trace.addTlsAction(new ConfiguredReceiveAction(new ClientHelloMessage()));
        WorkFlowTraceFakeExecuter.execute(trace);
        assertTrue(trace.getActuallyRecievedProtocolMessagesOfType(ProtocolMessageType.ALERT).size() == 1);
        assertTrue(trace.getActuallyRecievedProtocolMessagesOfType(ProtocolMessageType.HANDSHAKE).size() == 3);
        assertTrue(trace.getActuallyRecievedProtocolMessagesOfType(ProtocolMessageType.APPLICATION_DATA).isEmpty());
    }

    /**
     * Test of getActuallySentHandshakeMessagesOfType method, of class
     * WorkflowTrace.
     */
    @Test
    public void testGetActuallySentHandshakeMessagesOfType() {
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new CertificateMessage()));
        trace.addTlsAction(new SendAction(new AlertMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        WorkFlowTraceFakeExecuter.execute(trace);
        assertTrue(trace.getActuallySentHandshakeMessagesOfType(HandshakeMessageType.CERTIFICATE).size() == 1);
        assertTrue(trace.getActuallySentHandshakeMessagesOfType(HandshakeMessageType.CLIENT_HELLO).size() == 2);
        assertTrue(trace.getActuallySentHandshakeMessagesOfType(HandshakeMessageType.HELLO_VERIFY_REQUEST).isEmpty());
    }

    /**
     * Test of getActuallySentProtocolMessagesOfType method, of class
     * WorkflowTrace.
     */
    @Test
    public void testGetActuallySentProtocolMessagesOfType() {
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new CertificateMessage()));
        trace.addTlsAction(new SendAction(new AlertMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        WorkFlowTraceFakeExecuter.execute(trace);
        assertTrue(trace.getActuallySentProtocolMessagesOfType(ProtocolMessageType.ALERT).size() == 1);
        assertTrue(trace.getActuallySentProtocolMessagesOfType(ProtocolMessageType.HANDSHAKE).size() == 3);
        assertTrue(trace.getActuallySentProtocolMessagesOfType(ProtocolMessageType.APPLICATION_DATA).isEmpty());

    }

    /**
     * Test of getConfiguredRecievedHandshakeMessagesOfType method, of class
     * WorkflowTrace.
     */
    @Test
    public void testGetConfiguredRecievedHandshakeMessagesOfType() {
        trace.addTlsAction(new ConfiguredReceiveAction(new ClientHelloMessage()));
        trace.addTlsAction(new ConfiguredReceiveAction(new CertificateMessage()));
        trace.addTlsAction(new ConfiguredReceiveAction(new AlertMessage()));
        trace.addTlsAction(new ConfiguredReceiveAction(new ClientHelloMessage()));
        assertTrue(trace.getConfiguredRecievedHandshakeMessagesOfType(HandshakeMessageType.CERTIFICATE).size() == 1);
        assertTrue(trace.getConfiguredRecievedHandshakeMessagesOfType(HandshakeMessageType.CLIENT_HELLO).size() == 2);
        assertTrue(trace.getConfiguredRecievedHandshakeMessagesOfType(HandshakeMessageType.HELLO_VERIFY_REQUEST)
                .isEmpty());
    }

    /**
     * Test of getConfiguredRecievedProtocolMessagesOfType method, of class
     * WorkflowTrace.
     */
    @Test
    public void testGetConfiguredRecievedProtocolMessagesOfType() {
        trace.addTlsAction(new ConfiguredReceiveAction(new ClientHelloMessage()));
        trace.addTlsAction(new ConfiguredReceiveAction(new CertificateMessage()));
        trace.addTlsAction(new ConfiguredReceiveAction(new AlertMessage()));
        trace.addTlsAction(new ConfiguredReceiveAction(new ClientHelloMessage()));
        assertTrue(trace.getConfiguredRecievedProtocolMessagesOfType(ProtocolMessageType.ALERT).size() == 1);
        assertTrue(trace.getConfiguredRecievedProtocolMessagesOfType(ProtocolMessageType.HANDSHAKE).size() == 3);
        assertTrue(trace.getConfiguredRecievedProtocolMessagesOfType(ProtocolMessageType.APPLICATION_DATA).isEmpty());
    }

    /**
     * Test of getConfiguredSentHandshakeMessagesOfType method, of class
     * WorkflowTrace.
     */
    @Test
    public void testGetConfiguredSentHandshakeMessagesOfType() {
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new CertificateMessage()));
        trace.addTlsAction(new SendAction(new AlertMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        assertTrue(trace.getConfiguredSentHandshakeMessagesOfType(HandshakeMessageType.CERTIFICATE).size() == 1);
        assertTrue(trace.getConfiguredSentHandshakeMessagesOfType(HandshakeMessageType.CLIENT_HELLO).size() == 2);
        assertTrue(trace.getConfiguredSentHandshakeMessagesOfType(HandshakeMessageType.HELLO_VERIFY_REQUEST).isEmpty());
    }

    /**
     * Test of getConfiguredSendProtocolMessagesOfType method, of class
     * WorkflowTrace.
     */
    @Test
    public void testGetConfiguredSendProtocolMessagesOfType() {
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new CertificateMessage()));
        trace.addTlsAction(new SendAction(new AlertMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        assertTrue(trace.getConfiguredSendProtocolMessagesOfType(ProtocolMessageType.ALERT).size() == 1);
        assertTrue(trace.getConfiguredSendProtocolMessagesOfType(ProtocolMessageType.HANDSHAKE).size() == 3);
        assertTrue(trace.getConfiguredSendProtocolMessagesOfType(ProtocolMessageType.APPLICATION_DATA).isEmpty());
    }

    /**
     * Test of getAllConfiguredMessages method, of class WorkflowTrace.
     */
    @Test
    public void testGetAllConfiguredMessages() {
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new CertificateMessage()));
        trace.addTlsAction(new ChangeCipherSuiteAction());
        trace.addTlsAction(new ConfiguredReceiveAction(new AlertMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        assertTrue(trace.getAllConfiguredMessages().size() == 4);
    }

    /**
     * Test of getAllActualMessages method, of class WorkflowTrace.
     */
    @Test
    public void testGetAllActualMessages() {
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new CertificateMessage()));
        trace.addTlsAction(new ChangeCipherSuiteAction());
        trace.addTlsAction(new ConfiguredReceiveAction(new AlertMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        assertTrue(trace.getAllActualMessages().size() == 0);
        WorkFlowTraceFakeExecuter.execute(trace);
        assertTrue(trace.getAllActualMessages().size() == 4);
    }

    /**
     * Test of getAllConfiguredReceivingMessages method, of class WorkflowTrace.
     */
    @Test
    public void testGetAllConfiguredReceivingMessages() {
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new CertificateMessage()));
        trace.addTlsAction(new ChangeCipherSuiteAction());
        trace.addTlsAction(new ConfiguredReceiveAction(new AlertMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        assertTrue(trace.getAllConfiguredReceivingMessages().size() == 1);
        trace.addTlsAction(new ConfiguredReceiveAction(new AlertMessage()));
        assertTrue(trace.getAllConfiguredReceivingMessages().size() == 2);
    }

    /**
     * Test of getAllActuallyReceivedMessages method, of class WorkflowTrace.
     */
    @Test
    public void testGetAllActuallyReceivedMessages() {
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new CertificateMessage()));
        trace.addTlsAction(new ChangeCipherSuiteAction());
        trace.addTlsAction(new ConfiguredReceiveAction(new AlertMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        assertTrue(trace.getAllActuallyReceivedMessages().isEmpty());
        WorkFlowTraceFakeExecuter.execute(trace);
        assertTrue(trace.getAllActuallyReceivedMessages().size() == 1);
        trace.addTlsAction(new ConfiguredReceiveAction(new AlertMessage()));
        WorkFlowTraceFakeExecuter.execute(trace);
        assertTrue(trace.getAllActuallyReceivedMessages().size() == 2);

    }

    /**
     * Test of getAllConfiguredSendMessages method, of class WorkflowTrace.
     */
    @Test
    public void testGetAllConfiguredSendMessages() {
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new CertificateMessage()));
        trace.addTlsAction(new ChangeCipherSuiteAction());
        trace.addTlsAction(new ConfiguredReceiveAction(new AlertMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        assertTrue(trace.getAllConfiguredSendMessages().size() == 4);
        trace.addTlsAction(new SendAction(new AlertMessage()));
        assertTrue(trace.getAllConfiguredSendMessages().size() == 5);
    }

    /**
     * Test of getAllActuallySentMessages method, of class WorkflowTrace.
     */
    @Test
    public void testGetAllActuallySentMessages() {
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new CertificateMessage()));
        trace.addTlsAction(new ChangeCipherSuiteAction());
        trace.addTlsAction(new ConfiguredReceiveAction(new AlertMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        assertTrue(trace.getAllActuallySentMessages().isEmpty());
        WorkFlowTraceFakeExecuter.execute(trace);
        assertTrue(trace.getAllActuallySentMessages().size() == 4);
        trace.addTlsAction(new SendAction(new AlertMessage()));
        WorkFlowTraceFakeExecuter.execute(trace);
        assertTrue(trace.getAllActuallySentMessages().size() == 5);
    }

    /**
     * Test of getLastAction method, of class WorkflowTrace.
     */
    @Test
    public void testGetLastAction() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ConfiguredReceiveAction());
        trace.addTlsAction(new ConfiguredReceiveAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ConfiguredReceiveAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ChangeCipherSuiteAction());
        assertEquals(new ChangeCipherSuiteAction(), trace.getLastAction());
    }

    /**
     * Test of getLastMessageAction method, of class WorkflowTrace.
     */
    @Test
    public void testGetLastMessageAction() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ConfiguredReceiveAction());
        trace.addTlsAction(new ConfiguredReceiveAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ConfiguredReceiveAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ChangeCipherSuiteAction());
        assertEquals(new SendAction(), trace.getLastMessageAction());
        trace.addTlsAction(new ConfiguredReceiveAction());
        assertEquals(new ConfiguredReceiveAction(), trace.getLastMessageAction());
    }

    /**
     * Test of getLastConfiguredReceiveMesssage method, of class WorkflowTrace.
     */
    @Test
    public void testGetLastConfiguredReceiveMesssage() {
        trace.addTlsAction(new ChangeClientCertificateAction());
        trace.addTlsAction(new ConfiguredReceiveAction(new ApplicationMessage()));
        trace.addTlsAction(new SendAction(new ApplicationMessage()));
        trace.addTlsAction(new ConfiguredReceiveAction(new ClientHelloMessage()));
        assertEquals(trace.getLastConfiguredReceiveMesssage().toCompactString(),
                new ClientHelloMessage().toCompactString());
    }

    /**
     * Test of getLastConfiguredSendMesssage method, of class WorkflowTrace.
     */
    @Test
    public void testGetLastConfiguredSendMesssage() {
        trace.addTlsAction(new SendAction(new CertificateMessage()));
        trace.addTlsAction(new ChangeClientCertificateAction());
        trace.addTlsAction(new ConfiguredReceiveAction(new ApplicationMessage()));
        trace.addTlsAction(new SendAction(new ApplicationMessage()));
        trace.addTlsAction(new ConfiguredReceiveAction(new ClientHelloMessage()));
        assertEquals(trace.getLastConfiguredSendMesssage(), new ApplicationMessage());
    }

    /**
     * Test of containsConfiguredReceivedProtocolMessage method, of class
     * WorkflowTrace.
     */
    @Test
    public void testContainsConfiguredReceivedProtocolMessage() {
    }

    /**
     * Test of containsConfiguredSendProtocolMessage method, of class
     * WorkflowTrace.
     */
    @Test
    public void testContainsConfiguredSendProtocolMessage() {
    }

    /**
     * Test of actuallyReceivedTypeBeforeType method, of class WorkflowTrace.
     */
    @Test
    public void testActuallyReceivedTypeBeforeType_ProtocolMessageType_ProtocolMessageType() {
    }

    /**
     * Test of actuallyReceivedTypeBeforeType method, of class WorkflowTrace.
     */
    @Test
    public void testActuallyReceivedTypeBeforeType_ProtocolMessageType_HandshakeMessageType() {
    }

    /**
     * Test of configuredLooksLikeActual method, of class WorkflowTrace.
     */
    @Test
    public void testConfiguredLooksLikeActual() {
    }

    /**
     * Test of getFirstConfiguredSendActionWithType method, of class
     * WorkflowTrace.
     */
    @Test
    public void testGetFirstConfiguredSendActionWithType_ProtocolMessageType() {
    }

    /**
     * Test of getFirstConfiguredSendActionWithType method, of class
     * WorkflowTrace.
     */
    @Test
    public void testGetFirstConfiguredSendActionWithType_HandshakeMessageType() {
    }

    /**
     * Test of getName method, of class WorkflowTrace.
     */
    @Test
    public void testGetName() {
        trace.setName("testName");
        assertEquals("testName", trace.getName());
    }

    /**
     * Test of setName method, of class WorkflowTrace.
     */
    @Test
    public void testSetName() {
        trace.setName("testName");
        assertEquals("testName", trace.getName());
    }

    /**
     * Test of toString method, of class WorkflowTrace.
     */
    @Test
    public void testToString() {
    }

    /**
     * Test of hashCode method, of class WorkflowTrace.
     */
    @Test
    public void testHashCode() {
    }

    /**
     * Test of equals method, of class WorkflowTrace.
     */
    @Test
    public void testEquals() {
    }
}
