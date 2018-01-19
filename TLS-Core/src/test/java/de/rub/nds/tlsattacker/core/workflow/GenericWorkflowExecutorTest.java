/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
///**
// * TLS-Attacker - A Modular Penetration Testing Framework for TLS
// *
// * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
// *
// * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
// */
//package de.rub.nds.tlsattacker.tls.workflow;
//
//import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
//import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
//import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
//import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
//import de.rub.nds.tlsattacker.tls.protocol.application.ApplicationMessage;
//import de.rub.nds.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
//import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
//import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateMessage;
//import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
//import de.rub.nds.tlsattacker.tls.protocol.handshake.DHClientKeyExchangeMessage;
//import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
//import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
//import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
//import de.rub.nds.tlsattacker.tls.record.Record;
//import de.rub.nds.tlsattacker.tls.workflow.action.MessageActionFactory;
//import de.rub.nds.tlsattacker.tls.workflow.action.TLSAction;
//import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
//import de.rub.nds.tlsattacker.transport.TransportHandler;
//import java.util.LinkedList;
//import java.util.List;
//import mockit.Mocked;
//import mockit.NonStrictExpectations;
//import org.junit.Test;
//import static org.junit.Assert.*;
//
///**
// *

// */
//public class GenericWorkflowExecutorTest
//{
//
//    TlsContext context;
//    List<TLSAction> actions;
//
//    /**
//     * Test of executeWorkflow method, of class GenericWorkflowExecutor.
//     */
//    @Test
//    public void testExecuteWorkflow()
//    {
//
//    }
//
//    /**
//     * Test of prepareMyProtocolMessageBytes method, of class
//     * GenericWorkflowExecutor.
//     *
//     * @param mockedHandler
//     * @param mockedProtocolMessageMessage
//     * @param mockedTlsContext
//     */
//    @Test
//    public void testPrepareMyProtocolMessageBytes(@Mocked final ProtocolMessageHandler mockedHandler,
//            @Mocked final ProtocolMessage mockedProtocolMessageMessage, @Mocked final TlsContext mockedTlsContext)
//    {
//        // Record expectations if/as needed:
//        new NonStrictExpectations()
//        {
//            {
//                mockedHandler.prepareMessage();
//                result = new byte[2];
//                mockedTlsContext.getProtocolVersion();
//                result = ProtocolVersion.TLS12;
//                mockedProtocolMessageMessage.getProtocolMessageHandler(mockedTlsContext);
//                result = mockedHandler;
//                mockedProtocolMessageMessage.isGoingToBeSent();
//                result = true;
//            }
//        };
//
//        this.initializeContext();
//        GenericWorkflowExecutorImpl we = new GenericWorkflowExecutorImpl(null, mockedTlsContext);
//        we.prepareMyProtocolMessageBytes(mockedProtocolMessageMessage);
//        assertArrayEquals(new byte[2], we.messageBytesCollector.getProtocolMessageBytes());
//    }
//
//    /**
//     * Test of prepareMyRecordsIfNeeded method, of class
//     * GenericWorkflowExecutor.
//     */
//    @Test
//    public void testPrepareMyRecordsIfNeeded()
//    {
//        this.initializeContext();
//        GenericWorkflowExecutorImpl we = new GenericWorkflowExecutorImpl(null, context);
//        ProtocolMessage pm = context.getWorkflowTrace().getAllMessages().get(0);
//        we.messageBytesCollector.appendProtocolMessageBytes(new byte[2]);
//
//        we.prepareMyRecordsIfNeeded(pm);
//        assertTrue("protocol message bytes are still there",
//                we.messageBytesCollector.getProtocolMessageBytes().length == 2);
//        assertTrue("record bytes are empty", we.messageBytesCollector.getRecordBytes().length == 0);
//
//        List<Record> records = new LinkedList<>();
//        records.add(new Record());
//        pm.setRecords(records);
//        we.prepareMyRecordsIfNeeded(pm);
//        assertTrue("protocol message bytes were used for record creation",
//                we.messageBytesCollector.getProtocolMessageBytes().length == 0);
//        assertTrue("record bytes are not empty", we.messageBytesCollector.getRecordBytes().length > 0);
//    }
//
//    /**
//     * Test of removeNextProtocolMessages method, of class
//     * GenericWorkflowExecutor.
//     */
//    @Test
//    public void testRemoveNextProtocolMessages()
//    {
//        this.initializeContext();
//        GenericWorkflowExecutorImpl we = new GenericWorkflowExecutorImpl(null, context);
//        we.removeNextProtocolMessages(context.getWorkflowTrace().getAllMessages(), 2);
//        assertTrue("Only two messsages left in protocol messages", protocolMessages.size() == 2);
//        assertTrue(context.getWorkflowTrace().getAllMessages().get(0).getClass() == ClientHelloMessage.class);
//        assertTrue(context.getWorkflowTrace().getAllMessages().get(1).getClass() == ServerHelloMessage.class);
//    }
//
//    /**
//     * Test of handlingMyLastProtocolMessageWithContentType method, of class
//     * GenericWorkflowExecutor.
//     */
//    @Test
//    public void handlingMyLastProtocolMessageWithContentType()
//    {
//        this.initializeContext();
//        GenericWorkflowExecutorImpl we = new GenericWorkflowExecutorImpl(null, context);
//        assertTrue("ClientHello is last", we.handlingMyLastProtocolMessageWithContentType(context.getWorkflowTrace().getAllMessages(), 0));
//        assertTrue("ClientKeyExchange is last", we.handlingMyLastProtocolMessageWithContentType(context.getWorkflowTrace().getAllMessages(), 4));
//        assertTrue("ChangeCipherSpec is last", we.handlingMyLastProtocolMessageWithContentType(context.getWorkflowTrace().getAllMessages(), 5));
//        assertTrue("Finished is last", we.handlingMyLastProtocolMessageWithContentType(context.getWorkflowTrace().getAllMessages(), 6));
//    }
//
//    /**
//     * Test of handlingMyLastProtocolMessage method, of class
//     * GenericWorkflowExecutor.
//     */
//    @Test
//    public void handlingMyLastProtocolMessage()
//    {
//        this.initializeContext();
//        GenericWorkflowExecutorImpl we = new GenericWorkflowExecutorImpl(null, context);
//        assertTrue("ClientHello is last", we.handlingMyLastProtocolMessage(context.getWorkflowTrace().getAllMessages(), 0));
//        assertFalse("ClientKeyExchange is not last", we.handlingMyLastProtocolMessage(context.getWorkflowTrace().getAllMessages(), 4));
//        assertFalse("ChangeCipherSpec is not last", we.handlingMyLastProtocolMessage(context.getWorkflowTrace().getAllMessages(), 5));
//        assertTrue("Finished is last", we.handlingMyLastProtocolMessage(context.getWorkflowTrace().getAllMessages(), 6));
//    }
//
//    /**
//     * Test of ensureMyLastProtocolMessagesHaveRecords method, of class
//     * GenericWorkflowExecutor.
//     */
//    @Test
//    public void testEnsureMyLastProtocolMessagesHaveRecords()
//    {
//        this.initializeContext();
//        GenericWorkflowExecutorImpl we = new GenericWorkflowExecutorImpl(null, context);
//        we.ensureMyLastProtocolMessagesHaveRecords(context.getWorkflowTrace().getAllMessages());
//        assertFalse("ClientHello must have records", context.getWorkflowTrace().getAllMessages().get(0).getRecords().isEmpty());
//        assertFalse("ClientKeyExchange must have records", context.getWorkflowTrace().getAllMessages().get(4).getRecords().isEmpty());
//        assertFalse("ChangeCipherSpec must have records", context.getWorkflowTrace().getAllMessages().get(5).getRecords().isEmpty());
//        assertFalse("Finished must have records", context.getWorkflowTrace().getAllMessages().get(6).getRecords().isEmpty());
//        assertNull("First ApplicationMessage has no records", context.getWorkflowTrace().getAllMessages().get(9).getRecords());
//        assertFalse("Last ApplicationMessage must have records", context.getWorkflowTrace().getAllMessages().get(10).getRecords().isEmpty());
//    }
//
//    /**
//     * Test of createListsOfRecordsOfTheSameContentType method, of class
//     * GenericWorkflowExecutor.
//     */
//    @Test
//    public void testCreateListsOfRecordsOfTheSameContentType()
//    {
//        context = new TlsContext();
//        context.setProtocolVersion(ProtocolVersion.TLS12);
//        GenericWorkflowExecutorImpl we = new GenericWorkflowExecutorImpl(null, context);
//        List<Record> records = new LinkedList<>();
//        Record r = new Record();
//        r.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
//        records.add(r);
//        r = new Record();
//        r.setContentType(ProtocolMessageType.CHANGE_CIPHER_SPEC.getValue());
//        records.add(r);
//        r = new Record();
//        r.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
//        records.add(r);
//        List<List<Record>> result = we.createListsOfRecordsOfTheSameContentType(records);
//        assertEquals(3, result.size());
//        records.add(r);
//        result = we.createListsOfRecordsOfTheSameContentType(records);
//        assertEquals(3, result.size());
//    }
//
//    public class GenericWorkflowExecutorImpl extends GenericWorkflowExecutor
//    {
//        MessageBytesCollector messageBytesCollector;
//        public GenericWorkflowExecutorImpl(TransportHandler transportHandler, TlsContext tlsContext)
//        {
//            super(transportHandler, tlsContext, ExecutorType.TLS);
//            messageBytesCollector = new MessageBytesCollector();
//        }
//
//        protected void prepareMyProtocolMessageBytes(ProtocolMessage pm)
//        {
//            ProtocolMessageHandler handler = pm.getProtocolMessageHandler(tlsContext);
//            byte[] pmBytes = handler.prepareMessage();
//            // append the prepared protocol message bytes
//            if (pm.isGoingToBeSent())
//            {
//                messageBytesCollector.appendProtocolMessageBytes(pmBytes);
//            }
//        }
//
//    }
//
//    private void initializeContext()
//    {
//        context = new TlsContext();
//        context.setProtocolVersion(ProtocolVersion.TLS12);
//        actions = new LinkedList<>();
//        actions.add(MessageActionFactory.createAction(context.getMyConnectionEnd(), ConnectionEnd.CLIENT, new ClientHelloMessage()));
//        actions.add(MessageActionFactory.createAction(context.getMyConnectionEnd(), ConnectionEnd.SERVER, new ServerHelloMessage()));
//        actions.add(MessageActionFactory.createAction(context.getMyConnectionEnd(), ConnectionEnd.SERVER, new CertificateMessage()));
//        actions.add(MessageActionFactory.createAction(context.getMyConnectionEnd(), ConnectionEnd.SERVER, new ServerHelloDoneMessage()));
//        actions.add(MessageActionFactory.createAction(context.getMyConnectionEnd(), ConnectionEnd.CLIENT, new DHClientKeyExchangeMessage()));
//        actions.add(MessageActionFactory.createAction(context.getMyConnectionEnd(), ConnectionEnd.CLIENT, new ChangeCipherSpecMessage()));
//        actions.add(MessageActionFactory.createAction(context.getMyConnectionEnd(), ConnectionEnd.CLIENT, new FinishedMessage()));
//        actions.add(MessageActionFactory.createAction(context.getMyConnectionEnd(), ConnectionEnd.SERVER, new ChangeCipherSpecMessage()));
//        actions.add(MessageActionFactory.createAction(context.getMyConnectionEnd(), ConnectionEnd.SERVER, new FinishedMessage()));
//        actions.add(MessageActionFactory.createAction(context.getMyConnectionEnd(), ConnectionEnd.CLIENT, new ApplicationMessage()));
//        actions.add(MessageActionFactory.createAction(context.getMyConnectionEnd(), ConnectionEnd.SERVER, new ApplicationMessage()));
//    }
//
// }
