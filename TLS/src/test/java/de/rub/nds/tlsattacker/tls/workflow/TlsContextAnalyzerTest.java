/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.IntegerModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.application.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.tls.workflow.action.TLSAction;
import java.util.LinkedList;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class TlsContextAnalyzerTest {

    public TlsContextAnalyzerTest() {
    }

    /**
     * Test of getNextProtocolMessageFromPeer method, of class
     * TlsContextAnalyzer.
     */
    @Test
    public void testGetNextProtocolMessageFromPeer() {
	WorkflowConfigurationFactory factory = WorkflowConfigurationFactory.createInstance(new ClientCommandConfig());
	TlsContext context = factory.createFullServerResponseTlsContext(ConnectionEnd.CLIENT);
	context.setMyConnectionEnd(ConnectionEnd.CLIENT);

	ProtocolMessage pm = TlsContextAnalyzer.getNextReceiveProtocolMessage(context, 1);
	assertEquals(ProtocolMessageType.HANDSHAKE, pm.getProtocolMessageType());

	pm = TlsContextAnalyzer.getNextReceiveProtocolMessage(context, 3);
	assertEquals(ProtocolMessageType.CHANGE_CIPHER_SPEC, pm.getProtocolMessageType());
    }

    /**
     * Test of wasAlertAfterModifiedMessageSent method, of class
     * TlsContextAnalyzer.
     */
    @Test
    public void testContainsAlertAfterModifiedMessage() {
	WorkflowConfigurationFactory factory = WorkflowConfigurationFactory.createInstance(new ClientCommandConfig());
	TlsContext context = factory.createFullServerResponseTlsContext(ConnectionEnd.CLIENT);
	context.setMyConnectionEnd(ConnectionEnd.CLIENT);

	ApplicationMessage am = (ApplicationMessage) context.getWorkflowTrace().getFirstProtocolMessage(
		ProtocolMessageType.APPLICATION_DATA);
	ModifiableByteArray data = new ModifiableByteArray();
	data.setOriginalValue(new byte[0]);
	data.setModification(ByteArrayModificationFactory.explicitValue(new byte[] { 1 }));
	am.setData(data);

	assertEquals("There is no alert after modification.", TlsContextAnalyzer.AnalyzerResponse.NO_ALERT,
		TlsContextAnalyzer.containsAlertAfterModifiedMessage(context));
	ReceiveAction action = context.getWorkflowTrace().getReceiveActions().get(2);
	List<ProtocolMessage> messages = new LinkedList<>();
	messages.add(new AlertMessage());
	action.setConfiguredMessages(messages);
	context.getWorkflowTrace().add(new ReceiveAction(new AlertMessage()));
	// assertEquals("There is an alert after modification.",
	// TlsContextAnalyzer.AnalyzerResponse.ALERT,
	// TODO TlsContextAnalyzer.containsAlertAfterModifiedMessage(context));
    }

    // TODO NOT USED
    // /**
    // * Test of wasAlertAfterMissingMessageSent method, of class
    // * TlsContextAnalyzer.
    // */
    // @Test
    // public void testContainsAlertAfterMissingMessage() {
    // WorkflowConfigurationFactory factory =
    // WorkflowConfigurationFactory.createInstance(new ClientCommandConfig());
    // TlsContext context = factory.createFullTlsContext(ConnectionEnd.CLIENT);
    // context.setMyConnectionEnd(ConnectionEnd.CLIENT);
    //
    // assertEquals("There is no missing message",
    // TlsContextAnalyzer.AnalyzerResponse.NO_MODIFICATION,
    // TlsContextAnalyzer.containsAlertAfterMissingMessage(context));
    //
    // ProtocolMessage pm =
    // context.getWorkflowTrace().getFirstProtocolMessage(ProtocolMessageType.CHANGE_CIPHER_SPEC);
    // pm.setGoingToBeSent(false);
    //
    // assertEquals("There is no alert after a missing message.",
    // TlsContextAnalyzer.AnalyzerResponse.NO_ALERT,
    // TlsContextAnalyzer.containsAlertAfterMissingMessage(context));
    //
    // context.getWorkflowTrace().add(new ReceiveAction(new AlertMessage()));
    // assertEquals("There is no alert after a missing message (alert is sent at the end).",
    // TlsContextAnalyzer.AnalyzerResponse.NO_ALERT,
    // TlsContextAnalyzer.containsAlertAfterMissingMessage(context));
    //
    // int finishedPosition =
    // context.getWorkflowTrace().getHandshakeMessagePositions(HandshakeMessageType.FINISHED)
    // .get(0);
    // context.getWorkflowTrace().add(new ReceiveAction(new AlertMessage()));
    // assertEquals("There is an alert after a missing message.",
    // TlsContextAnalyzer.AnalyzerResponse.ALERT,
    // TlsContextAnalyzer.containsAlertAfterMissingMessage(context));
    // }

    // /** TODO Deprecated
    // * Test of wasAlertAfterUnexpectedMessageSent method, of class
    // * TlsContextAnalyzer.
    // */
    // @Test
    // public void testContainsAlertAfterUnexpectedMessage() {
    // WorkflowConfigurationFactory factory =
    // WorkflowConfigurationFactory.createInstance(new ClientCommandConfig());
    // TlsContext context = factory.createFullTlsContext(ConnectionEnd.CLIENT);
    // context.setMyConnectionEnd(ConnectionEnd.CLIENT);
    //
    // assertEquals("There is no unexpected message",
    // TlsContextAnalyzer.AnalyzerResponse.NO_MODIFICATION,
    // TlsContextAnalyzer.containsAlertAfterUnexpectedMessage(context));
    //
    // int position =
    // context.getWorkflowTrace().getProtocolMessagePositions(ProtocolMessageType.CHANGE_CIPHER_SPEC)
    // .get(0);
    // context.getWorkflowTrace().add(new SendAction(new
    // ChangeCipherSpecMessage()));
    //
    // assertEquals("There is no alert after an unexpected message.",
    // TlsContextAnalyzer.AnalyzerResponse.NO_ALERT,
    // TlsContextAnalyzer.containsAlertAfterUnexpectedMessage(context));
    //
    // context.getWorkflowTrace().add(new ReceiveAction(new AlertMessage()));
    // assertEquals("There is no alert after an unexpected message (alert is sent at the end).",
    // TlsContextAnalyzer.AnalyzerResponse.NO_ALERT,
    // TlsContextAnalyzer.containsAlertAfterUnexpectedMessage(context));
    //
    // context.getWorkflowTrace().add(new ReceiveAction(new AlertMessage()));
    // assertEquals("There is an alert after an unexpected message.",
    // TlsContextAnalyzer.AnalyzerResponse.ALERT,
    // TlsContextAnalyzer.containsAlertAfterUnexpectedMessage(context));
    //
    // context.getWorkflowTrace().add(new ReceiveAction(new AlertMessage()));
    // assertEquals("There is an alert after an unexpected message.",
    // TlsContextAnalyzer.AnalyzerResponse.ALERT,
    // TlsContextAnalyzer.containsAlertAfterUnexpectedMessage(context));
    // /*
    // context.getWorkflowTrace().setProtocolMessages(context.getWorkflowTrace().getProtocolMessages().subList(0,
    // 2));
    // assertEquals("There is an alert after a ClientHello message.",
    // TlsContextAnalyzer.AnalyzerResponse.NO_MODIFICATION,
    // TlsContextAnalyzer.containsAlertAfterUnexpectedMessage(context));
    // TODO
    // */
    // }

    /**
     * Test of testContainsModifiedMessage method, of class TlsContextAnalyzer.
     */
    @Test
    public void testContainsModifiedMessage() {
	WorkflowConfigurationFactory factory = WorkflowConfigurationFactory.createInstance(new ClientCommandConfig());
	TlsContext context = factory.createFullServerResponseTlsContext(ConnectionEnd.CLIENT);
	context.setMyConnectionEnd(ConnectionEnd.CLIENT);

	assertFalse("There schouldnt be a modification.", TlsContextAnalyzer.containsModifiedMessage(context));

	ApplicationMessage am = (ApplicationMessage) context.getWorkflowTrace().getFirstProtocolMessage(
		ProtocolMessageType.APPLICATION_DATA);
	ModifiableByteArray data = new ModifiableByteArray();
	data.setOriginalValue(new byte[] { 1 });
	data.setModification(ByteArrayModificationFactory.explicitValue(new byte[0]));
	am.setData(data);

	assertTrue("There schould be a modification.", TlsContextAnalyzer.containsModifiedMessage(context));
    }

    /**
     * Test of testContainsMissingMessage method, of class TlsContextAnalyzer.
     */
    @Test
    public void testContainsMissingMessage() {
	WorkflowConfigurationFactory factory = WorkflowConfigurationFactory.createInstance(new ClientCommandConfig());
	TlsContext context = factory.createFullTlsContext(ConnectionEnd.CLIENT);
	context.setMyConnectionEnd(ConnectionEnd.CLIENT);

	assertFalse("There is no missing message", TlsContextAnalyzer.containsMissingMessage(context));

	ProtocolMessage pm = context.getWorkflowTrace().getFirstProtocolMessage(ProtocolMessageType.CHANGE_CIPHER_SPEC);
	pm.setGoingToBeSent(false);

	assertTrue("There is a missing message.", TlsContextAnalyzer.containsMissingMessage(context));
    }

    /**
     * Test of testContainsUnexpectedMessage method, of class
     * TlsContextAnalyzer.
     */
    @Test
    public void testContainsUnexpectedMessage() {
	WorkflowConfigurationFactory factory = WorkflowConfigurationFactory.createInstance(new ClientCommandConfig());
	TlsContext context = factory.createFullTlsContext(ConnectionEnd.CLIENT);
	context.setMyConnectionEnd(ConnectionEnd.CLIENT);
	for (ReceiveAction action : context.getWorkflowTrace().getReceiveActions()) {
	    for (ProtocolMessage tempMessage : action.getConfiguredMessages()) {
		action.getActualMessages().add(tempMessage);
	    }

	}
	assertFalse("There shouldnt be an unexpeted Message",
		TlsContextAnalyzer.containsUnexpectedMessage(context.getWorkflowTrace()));
	context.getWorkflowTrace().add(new ReceiveAction(new ChangeCipherSpecMessage())); // Because
											  // we
											  // didnt
											  // actually
											  // receive
											  // this
											  // message
	assertTrue("There should be an unexpected Message",
		TlsContextAnalyzer.containsUnexpectedMessage(context.getWorkflowTrace()));
	context.getWorkflowTrace().remove(context.getWorkflowTrace().getTLSActions().size() - 1);
	assertFalse("There shouldnt be an unexpeted Message",
		TlsContextAnalyzer.containsUnexpectedMessage(context.getWorkflowTrace()));
	ReceiveAction action = context.getWorkflowTrace().getReceiveActions().get(1);
	action.getActualMessages().add(new AlertMessage()); // Because
							    // we
							    // didnt
							    // configure
							    // this
							    // message
	assertTrue("There should be an unexpected Message",
		TlsContextAnalyzer.containsUnexpectedMessage(context.getWorkflowTrace()));
	action.getActualMessages().remove(action.getActualMessages().size() - 1);
	assertFalse("There shouldnt be an unexpeted Message",
		TlsContextAnalyzer.containsUnexpectedMessage(context.getWorkflowTrace()));
	action.getActualMessages().remove(0);
	action.getActualMessages().add(0, new ServerHelloDoneMessage());
	assertTrue("There should be an unexpected Message",
		TlsContextAnalyzer.containsUnexpectedMessage(context.getWorkflowTrace()));

    }

    /**
     * Test of containsModifiableVariableModification method, of class
     * TlsContextAnalyzer.
     */
    @Test
    public void testContainsModifiableVariableModification() {
	ClientHelloMessage ch = new ClientHelloMessage();
	assertFalse("This ClientHello message contains no modification",
		TlsContextAnalyzer.containsModifiableVariableModification(ch));
	ch.setCipherSuiteLength(2);
	assertFalse("This ClientHello message contains no modification",
		TlsContextAnalyzer.containsModifiableVariableModification(ch));
	ModifiableInteger length = new ModifiableInteger();
	length.setOriginalValue(2);
	length.setModification(IntegerModificationFactory.add(1));
	ch.setCipherSuiteLength(length);
	assertTrue("This ClientHello message contains a modification in the CipherSuite Length variable",
		TlsContextAnalyzer.containsModifiableVariableModification(ch));

	ch = new ClientHelloMessage();
	List<Record> records = new LinkedList<>();
	Record r = new Record();
	r.setLength(length);
	records.add(r);
	ch.setRecords(records);
	assertTrue("This ClientHello message contains a modification in the record Length variable",
		TlsContextAnalyzer.containsModifiableVariableModification(ch));
    }

}
