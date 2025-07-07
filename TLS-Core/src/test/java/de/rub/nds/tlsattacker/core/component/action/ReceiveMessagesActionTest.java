/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.component.action;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.*;
import java.util.LinkedList;
import java.util.List;
import org.junit.Test;

/** Component test that covers receive actions in DTLS */
public class ReceiveMessagesActionTest extends ActionComponentTest {

    /**
     * Tests whether the ServerHello message in the server flight is received as planned via
     * ReceiveTillAction
     */
    @Test
    public void testReceiveTillServerHello() {
        WorkflowTrace trace = createTrace();
        trace.addTlsAction(new ReceiveTillAction(SERVER_CTX_ALIAS, new ServerHelloMessage()));

        initAndExecute(trace, new byte[0], PacketLibrary.FRAGMENTED_DTLS_SERVER_FLIGHT);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());

        initAndExecute(trace, new byte[0], PacketLibrary.WHOLE_DTLS_SERVER_FLIGHT);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
    }

    /** Tests whether the Certificate message is received as planned via ReceiveTillAction */
    @Test
    public void testReceiveTillServerCertificate() {
        WorkflowTrace trace = createTrace();
        trace.addTlsAction(new ReceiveTillAction(SERVER_CTX_ALIAS, new CertificateMessage()));

        initAndExecute(trace, new byte[0], PacketLibrary.FRAGMENTED_DTLS_SERVER_FLIGHT);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());

        initAndExecute(trace, new byte[0], PacketLibrary.WHOLE_DTLS_SERVER_FLIGHT);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
    }

    /** Tests whether the Certificate message is received as planned via ReceiveTillAction */
    @Test
    public void testReceiveTillClientCertificate() {
        WorkflowTrace trace = createTrace();
        trace.addTlsAction(new ReceiveTillAction(CLIENT_CTX_ALIAS, new CertificateMessage()));

        initAndExecute(trace, PacketLibrary.CLIENT_CERT_TILL_FINISHED, new byte[0]);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
    }

    /** Tests whether the Certificate message is received as planned via ReceiveTillAction */
    @Test
    public void testReceiveTillClientChangeCipherSpec() {
        WorkflowTrace trace = createTrace();
        trace.addTlsAction(new ReceiveTillAction(CLIENT_CTX_ALIAS, new ChangeCipherSpecMessage()));

        initAndExecute(trace, PacketLibrary.CLIENT_CERT_TILL_FINISHED, new byte[0]);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
    }

    /** Tests whether the Certificate message is received as planned via BufferedReceiveAction */
    @Test
    public void testBufferedReceive() {
        WorkflowTrace trace = createTrace();
        trace.addTlsAction(
                new BufferedReceiveAction(
                        CLIENT_CTX_ALIAS,
                        new CertificateMessage(),
                        new ECDHClientKeyExchangeMessage(),
                        new CertificateVerifyMessage(),
                        new ChangeCipherSpecMessage()));

        initAndExecute(trace, PacketLibrary.CLIENT_CERT_TILL_FINISHED, new byte[0]);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
    }

    /**
     * Tests whether the Certificate message is received as planned via BufferedReceiveAction and
     * adds additional actions to the trace
     */
    @Test
    public void testBufferedReceiveAndPop() {
        WorkflowTrace trace = createTrace();

        trace.addTlsAction(
                new ForwardMessagesAction(
                        SERVER_CTX_ALIAS,
                        CLIENT_CTX_ALIAS,
                        new ServerHelloMessage(),
                        new CertificateMessage(),
                        new ECDHEServerKeyExchangeMessage(),
                        new CertificateRequestMessage(),
                        new ServerHelloDoneMessage()));

        trace.addTlsAction(
                new BufferedReceiveAction(
                        CLIENT_CTX_ALIAS,
                        new CertificateMessage(),
                        new ECDHClientKeyExchangeMessage(),
                        new CertificateVerifyMessage(),
                        new ChangeCipherSpecMessage()));

        trace.addTlsAction(new CopyBufferedMessagesAction(CLIENT_CTX_ALIAS, SERVER_CTX_ALIAS));
        trace.addTlsAction(new PopAndSendAction(SERVER_CTX_ALIAS));

        trace.addTlsAction(new SendDynamicClientKeyExchangeAction(SERVER_CTX_ALIAS));
        trace.addTlsAction(new ResetConnectionAction(SERVER_CTX_ALIAS));
        trace.addTlsAction(new SendAction(SERVER_CTX_ALIAS, new ClientHelloMessage()));

        initAndExecute(
                trace,
                PacketLibrary.CLIENT_CERT_TILL_FINISHED,
                PacketLibrary.WHOLE_DTLS_SERVER_FLIGHT);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
        assertDataWrittenToServer();
    }

    /** Tests whether a Server Flight is correctly received if a retransmission follows */
    @Test
    public void testReceiveWithRetransmission() {
        WorkflowTrace trace = createTrace();
        trace.addTlsAction(
                new ReceiveAction(
                        SERVER_CTX_ALIAS,
                        new ServerHelloMessage(),
                        new CertificateMessage(),
                        new ECDHEServerKeyExchangeMessage(),
                        new CertificateRequestMessage(),
                        new ServerHelloDoneMessage()));

        // create transport handler input for server context: server flight incl one retransmission
        byte[] serverFlightWithRetransmissison =
                arrayJoin(
                        List.of(
                                PacketLibrary.WHOLE_DTLS_SERVER_FLIGHT,
                                PacketLibrary.WHOLE_DTLS_SERVER_FLIGHT_RETRANSMISSION));

        initAndExecute(trace, new byte[0], serverFlightWithRetransmissison);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
    }

    /**
     * Tests whether a Client Certificate etc is correctly received if multiple, fragmented
     * retransmissions follow
     */
    @Test
    public void testReceiveTillWithRetransmissionIgnoreCss() {

        // explicitly set to ignore ccs retransmission
        getConfig().setIgnoreRetransmittedCssInDtls(true);

        WorkflowTrace trace = createTrace();
        ReceiveTillAction receiveTillAction =
                new ReceiveTillAction(CLIENT_CTX_ALIAS, new ChangeCipherSpecMessage());
        trace.addTlsAction(receiveTillAction);

        // create transport handler input for server context: server flight incl one retransmission
        byte[] udpPayloads =
                arrayJoin(
                        List.of(
                                PacketLibrary.CLIENT_CERT_TILL_FINISHED_2,
                                PacketLibrary.CLIENT_CERT_TILL_FINISHED_2_RETRANSMISSION_1,
                                PacketLibrary.CLIENT_CERT_TILL_FINISHED_2_RETRANSMISSION_2,
                                PacketLibrary.CLIENT_CERT_TILL_FINISHED_2_RETRANSMISSION_3,
                                PacketLibrary.CLIENT_CERT_TILL_FINISHED_2_RETRANSMISSION_4,
                                PacketLibrary.CLIENT_CERT_TILL_FINISHED_2_RETRANSMISSION_5,
                                PacketLibrary.CLIENT_CERT_TILL_FINISHED_2_RETRANSMISSION_6));

        initAndExecute(trace, udpPayloads, new byte[0]);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());

        long ccsReceived =
                receiveTillAction
                        .getLayerStackProcessingResult()
                        .getLayerProcessingResultList()
                        .getFirst()
                        .getUsedContainers()
                        .stream()
                        .filter(m -> m instanceof ChangeCipherSpecMessage)
                        .count();
        assertEquals(1, ccsReceived);
    }

    @Test
    public void testReceiveUnorderedServerFlight1() {
        WorkflowTrace trace = createTrace();
        trace.addTlsAction(
                new ReceiveAction(
                        SERVER_CTX_ALIAS,
                        new ServerHelloMessage(),
                        new CertificateMessage(),
                        new ECDHEServerKeyExchangeMessage(),
                        new ServerHelloDoneMessage()));

        getConfig().setReorderReceivedDtlsRecords(true);

        byte[] udpPayloads =
                arrayJoin(
                        List.of(
                                PacketLibrary.SERVER_FLIGHT_TILL_SHD_3_1,
                                PacketLibrary.SERVER_FLIGHT_TILL_SHD_3_2,
                                PacketLibrary.SERVER_FLIGHT_TILL_SHD_3_3,
                                PacketLibrary.SERVER_FLIGHT_TILL_SHD_3_4));

        initAndExecute(trace, new byte[0], udpPayloads);

        getConfig().setReorderReceivedDtlsRecords(false);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
    }

    @Test
    public void testFailToParseReceiveUnorderedServerFlight1() {
        WorkflowTrace trace = createTrace();
        trace.addTlsAction(
                new ReceiveAction(
                        SERVER_CTX_ALIAS,
                        new ServerHelloMessage(),
                        new CertificateMessage(),
                        new ECDHEServerKeyExchangeMessage(),
                        new ServerHelloDoneMessage()));

        getConfig().setReorderReceivedDtlsRecords(false);

        byte[] udpPayloads =
                arrayJoin(
                        List.of(
                                PacketLibrary.SERVER_FLIGHT_TILL_SHD_3_1,
                                PacketLibrary.SERVER_FLIGHT_TILL_SHD_3_2,
                                PacketLibrary.SERVER_FLIGHT_TILL_SHD_3_3,
                                PacketLibrary.SERVER_FLIGHT_TILL_SHD_3_4));

        initAndExecute(trace, new byte[0], udpPayloads);

        assertFalse(trace.executedAsPlanned());
    }

    @Test
    public void testReceiveUnorderedServerFlight2() {
        WorkflowTrace trace = createTrace();
        trace.addTlsAction(
                new ReceiveAction(
                        SERVER_CTX_ALIAS,
                        new ServerHelloMessage(),
                        new CertificateMessage(),
                        new ECDHEServerKeyExchangeMessage(),
                        new ServerHelloDoneMessage()));

        getConfig().setReorderReceivedDtlsRecords(true);

        byte[] udpPayloads =
                arrayJoin(
                        List.of(
                                PacketLibrary.SERVER_FLIGHT_TILL_SHD_4_1,
                                PacketLibrary.SERVER_FLIGHT_TILL_SHD_4_2,
                                PacketLibrary.SERVER_FLIGHT_TILL_SHD_4_3,
                                PacketLibrary.SERVER_FLIGHT_TILL_SHD_4_4));
        initAndExecute(trace, new byte[0], udpPayloads);

        getConfig().setReorderReceivedDtlsRecords(false);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
    }

    @Test
    public void testFailToParseReceiveUnorderedServerFlight2() {
        WorkflowTrace trace = createTrace();
        trace.addTlsAction(
                new ReceiveAction(
                        SERVER_CTX_ALIAS,
                        new ServerHelloMessage(),
                        new CertificateMessage(),
                        new ECDHEServerKeyExchangeMessage(),
                        new ServerHelloDoneMessage()));

        getConfig().setReorderReceivedDtlsRecords(false);

        byte[] udpPayloads =
                arrayJoin(
                        List.of(
                                PacketLibrary.SERVER_FLIGHT_TILL_SHD_4_1,
                                PacketLibrary.SERVER_FLIGHT_TILL_SHD_4_2,
                                PacketLibrary.SERVER_FLIGHT_TILL_SHD_4_3,
                                PacketLibrary.SERVER_FLIGHT_TILL_SHD_4_4));

        initAndExecute(trace, new byte[0], udpPayloads);

        assertFalse(trace.executedAsPlanned());
    }

    @Test
    public void testReceiveUnorderedServerFlight3() {
        WorkflowTrace trace = createTrace();

        List<ProtocolMessage> expectedMessages = new LinkedList<>();
        expectedMessages.add(new ServerHelloMessage());
        ProtocolMessage tempMessage = new CertificateMessage();
        tempMessage.setRequired(false);
        expectedMessages.add(tempMessage);
        tempMessage = new ECDHEServerKeyExchangeMessage();
        tempMessage.setRequired(false);
        expectedMessages.add(tempMessage);
        tempMessage = new DHEServerKeyExchangeMessage();
        tempMessage.setRequired(false);
        expectedMessages.add(tempMessage);
        tempMessage = new CertificateRequestMessage();
        tempMessage.setRequired(false);
        expectedMessages.add(tempMessage);
        expectedMessages.add(new ServerHelloDoneMessage());

        trace.addTlsAction(
                new ForwardMessagesAction(SERVER_CTX_ALIAS, CLIENT_CTX_ALIAS, expectedMessages));

        getConfig().setReorderReceivedDtlsRecords(true);

        byte[] udpPayloads =
                arrayJoin(
                        List.of(
                                PacketLibrary.SERVER_FLIGHT_TILL_SHD_7_1,
                                PacketLibrary.SERVER_FLIGHT_TILL_SHD_7_2,
                                PacketLibrary.SERVER_FLIGHT_TILL_SHD_7_3,
                                PacketLibrary.SERVER_FLIGHT_TILL_SHD_7_4));
        initAndExecute(trace, new byte[0], udpPayloads);

        getConfig().setReorderReceivedDtlsRecords(false);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
    }
}
