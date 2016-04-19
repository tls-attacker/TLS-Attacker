/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.application.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.util.LinkedList;
import java.util.List;
import mockit.Mocked;
import mockit.NonStrictExpectations;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class GenericWorkflowExecutorTest {

    TlsContext context;
    List<ProtocolMessage> protocolMessages;

    /**
     * Test of executeWorkflow method, of class GenericWorkflowExecutor.
     */
    @Test
    public void testExecuteWorkflow() {

    }

    /**
     * Test of prepareMyProtocolMessageBytes method, of class
     * GenericWorkflowExecutor.
     * 
     * @param mockedHandler
     * @param mockedProtocolMessageMessage
     * @param mockedTlsContext
     */
    @Test
    public void testPrepareMyProtocolMessageBytes(@Mocked final ProtocolMessageHandler mockedHandler,
	    @Mocked final ProtocolMessage mockedProtocolMessageMessage, @Mocked final TlsContext mockedTlsContext) {
	// Record expectations if/as needed:
	new NonStrictExpectations() {
	    {
		mockedHandler.prepareMessage();
		result = new byte[2];
		mockedTlsContext.getProtocolVersion();
		result = ProtocolVersion.TLS12;
		mockedProtocolMessageMessage.getProtocolMessageHandler(mockedTlsContext);
		result = mockedHandler;
		mockedProtocolMessageMessage.isGoingToBeSent();
		result = true;
	    }
	};

	this.initializeContext();
	GenericWorkflowExecutorImpl we = new GenericWorkflowExecutorImpl(null, mockedTlsContext);
	we.prepareMyProtocolMessageBytes(mockedProtocolMessageMessage);
	assertArrayEquals(new byte[2], we.messageBytesCollector.getProtocolMessageBytes());
    }

    /**
     * Test of prepareMyRecordsIfNeeded method, of class
     * GenericWorkflowExecutor.
     */
    @Test
    public void testPrepareMyRecordsIfNeeded() {
	this.initializeContext();
	GenericWorkflowExecutorImpl we = new GenericWorkflowExecutorImpl(null, context);
	ProtocolMessage pm = protocolMessages.get(0);
	we.messageBytesCollector.appendProtocolMessageBytes(new byte[2]);

	we.prepareMyRecordsIfNeeded(pm);
	assertTrue("protocol message bytes are still there",
		we.messageBytesCollector.getProtocolMessageBytes().length == 2);
	assertTrue("record bytes are empty", we.messageBytesCollector.getRecordBytes().length == 0);

	List<Record> records = new LinkedList<>();
	records.add(new Record());
	pm.setRecords(records);
	we.prepareMyRecordsIfNeeded(pm);
	assertTrue("protocol message bytes were used for record creation",
		we.messageBytesCollector.getProtocolMessageBytes().length == 0);
	assertTrue("record bytes are not empty", we.messageBytesCollector.getRecordBytes().length > 0);
    }

    /**
     * Test of removeNextProtocolMessages method, of class
     * GenericWorkflowExecutor.
     */
    @Test
    public void testRemoveNextProtocolMessages() {
	this.initializeContext();
	GenericWorkflowExecutorImpl we = new GenericWorkflowExecutorImpl(null, context);
	we.removeNextProtocolMessages(protocolMessages, 2);
	assertTrue("Only two messsages left in protocol messages", protocolMessages.size() == 2);
	assertTrue(protocolMessages.get(0).getClass() == ClientHelloMessage.class);
	assertTrue(protocolMessages.get(1).getClass() == ServerHelloMessage.class);
    }

    /**
     * Test of handlingMyLastProtocolMessageWithContentType method, of class
     * GenericWorkflowExecutor.
     */
    @Test
    public void handlingMyLastProtocolMessageWithContentType() {
	this.initializeContext();
	GenericWorkflowExecutorImpl we = new GenericWorkflowExecutorImpl(null, context);
	assertTrue("ClientHello is last", we.handlingMyLastProtocolMessageWithContentType(protocolMessages, 0));
	assertTrue("ClientKeyExchange is last", we.handlingMyLastProtocolMessageWithContentType(protocolMessages, 4));
	assertTrue("ChangeCipherSpec is last", we.handlingMyLastProtocolMessageWithContentType(protocolMessages, 5));
	assertTrue("Finished is last", we.handlingMyLastProtocolMessageWithContentType(protocolMessages, 6));
    }

    /**
     * Test of handlingMyLastProtocolMessage method, of class
     * GenericWorkflowExecutor.
     */
    @Test
    public void handlingMyLastProtocolMessage() {
	this.initializeContext();
	GenericWorkflowExecutorImpl we = new GenericWorkflowExecutorImpl(null, context);
	assertTrue("ClientHello is last", we.handlingMyLastProtocolMessage(protocolMessages, 0));
	assertFalse("ClientKeyExchange is not last", we.handlingMyLastProtocolMessage(protocolMessages, 4));
	assertFalse("ChangeCipherSpec is not last", we.handlingMyLastProtocolMessage(protocolMessages, 5));
	assertTrue("Finished is last", we.handlingMyLastProtocolMessage(protocolMessages, 6));
    }

    /**
     * Test of ensureMyLastProtocolMessagesHaveRecords method, of class
     * GenericWorkflowExecutor.
     */
    @Test
    public void testEnsureMyLastProtocolMessagesHaveRecords() {
	this.initializeContext();
	GenericWorkflowExecutorImpl we = new GenericWorkflowExecutorImpl(null, context);
	we.ensureMyLastProtocolMessagesHaveRecords(protocolMessages);
	assertFalse("ClientHello must have records", protocolMessages.get(0).getRecords().isEmpty());
	assertFalse("ClientKeyExchange must have records", protocolMessages.get(4).getRecords().isEmpty());
	assertFalse("ChangeCipherSpec must have records", protocolMessages.get(5).getRecords().isEmpty());
	assertFalse("Finished must have records", protocolMessages.get(6).getRecords().isEmpty());
	assertNull("First ApplicationMessage has no records", protocolMessages.get(9).getRecords());
	assertFalse("Last ApplicationMessage must have records", protocolMessages.get(10).getRecords().isEmpty());
    }

    /**
     * Test of createListsOfRecordsOfTheSameContentType method, of class
     * GenericWorkflowExecutor.
     */
    @Test
    public void testCreateListsOfRecordsOfTheSameContentType() {
	context = new TlsContext();
	context.setProtocolVersion(ProtocolVersion.TLS12);
	GenericWorkflowExecutorImpl we = new GenericWorkflowExecutorImpl(null, context);
	List<Record> records = new LinkedList<>();
	Record r = new Record();
	r.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
	records.add(r);
	r = new Record();
	r.setContentType(ProtocolMessageType.CHANGE_CIPHER_SPEC.getValue());
	records.add(r);
	r = new Record();
	r.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
	records.add(r);
	List<List<Record>> result = we.createListsOfRecordsOfTheSameContentType(records);
	assertEquals(3, result.size());
	records.add(r);
	result = we.createListsOfRecordsOfTheSameContentType(records);
	assertEquals(3, result.size());
    }

    public class GenericWorkflowExecutorImpl extends GenericWorkflowExecutor {

	public GenericWorkflowExecutorImpl(TransportHandler transportHandler, TlsContext tlsContext) {
	    super(transportHandler, tlsContext);
	}
    }

    private void initializeContext() {
	context = new TlsContext();
	context.setProtocolVersion(ProtocolVersion.TLS12);
	protocolMessages = new LinkedList<>();
	protocolMessages.add(new ClientHelloMessage(ConnectionEnd.CLIENT));
	protocolMessages.add(new ServerHelloMessage(ConnectionEnd.SERVER));
	protocolMessages.add(new CertificateMessage(ConnectionEnd.SERVER));
	protocolMessages.add(new ServerHelloDoneMessage(ConnectionEnd.SERVER));
	protocolMessages.add(new DHClientKeyExchangeMessage(ConnectionEnd.CLIENT));
	protocolMessages.add(new ChangeCipherSpecMessage(ConnectionEnd.CLIENT));
	protocolMessages.add(new FinishedMessage(ConnectionEnd.CLIENT));
	protocolMessages.add(new ChangeCipherSpecMessage(ConnectionEnd.SERVER));
	protocolMessages.add(new FinishedMessage(ConnectionEnd.SERVER));
	protocolMessages.add(new ApplicationMessage(ConnectionEnd.CLIENT));
	protocolMessages.add(new ApplicationMessage(ConnectionEnd.CLIENT));
    }

}
