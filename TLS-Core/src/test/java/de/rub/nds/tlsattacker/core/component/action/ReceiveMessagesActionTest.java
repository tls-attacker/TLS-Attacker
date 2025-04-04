/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.component.action;

import static org.junit.Assert.assertTrue;

import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.BufferedReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
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
}
