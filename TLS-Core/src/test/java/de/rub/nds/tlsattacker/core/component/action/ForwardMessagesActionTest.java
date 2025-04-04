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
import de.rub.nds.tlsattacker.core.workflow.action.*;
import org.junit.Test;

/** Component test that covers forward actions in DTLS */
public class ForwardMessagesActionTest extends ActionComponentTest {

    /**
     * Tests whether the Certificate message in the server flight can be forwarded as planned via
     * TightForwardTillAction
     */
    @Test
    public void testBaselineTightForwardCertificate() {
        WorkflowTrace trace = createTrace();
        trace.addTlsAction(
                new TightForwardTillAction(
                        SERVER_CTX_ALIAS, CLIENT_CTX_ALIAS, new CertificateMessage()));

        initAndExecute(trace, new byte[0], PacketLibrary.FRAGMENTED_DTLS_SERVER_FLIGHT);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
        assertDataWrittenToClient();

        initAndExecute(trace, new byte[0], PacketLibrary.WHOLE_DTLS_SERVER_FLIGHT);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
        assertDataWrittenToClient();
    }

    /**
     * Tests whether the ServerHello message in the server flight can be forwarded as planned via
     * TightForwardTillAction
     */
    @Test
    public void testBaselineTightForwardServerHello() {
        WorkflowTrace trace = createTrace();
        trace.addTlsAction(
                new TightForwardTillAction(
                        SERVER_CTX_ALIAS, CLIENT_CTX_ALIAS, new ServerHelloMessage()));

        initAndExecute(trace, new byte[0], PacketLibrary.FRAGMENTED_DTLS_SERVER_FLIGHT);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
        assertDataWrittenToClient();

        initAndExecute(trace, new byte[0], PacketLibrary.WHOLE_DTLS_SERVER_FLIGHT);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
        assertDataWrittenToClient();
    }

    /**
     * Tests whether the ServerHello of the trace can be tightly forwarded and the certificate
     * message be received as planned
     */
    @Test
    public void testTightForwardAndProcessTrailing() {
        WorkflowTrace trace = createTrace();
        trace.addTlsAction(
                new TightForwardTillAction(
                        SERVER_CTX_ALIAS, CLIENT_CTX_ALIAS, new ServerHelloMessage()));
        trace.addTlsAction(
                new ReceiveAction(
                        SERVER_CTX_ALIAS,
                        new CertificateMessage(),
                        new ECDHEServerKeyExchangeMessage(),
                        new CertificateRequestMessage(),
                        new ServerHelloDoneMessage()));

        initAndExecute(trace, new byte[0], PacketLibrary.FRAGMENTED_DTLS_SERVER_FLIGHT);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
        assertDataWrittenToClient();

        initAndExecute(trace, new byte[0], PacketLibrary.WHOLE_DTLS_SERVER_FLIGHT);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
        assertDataWrittenToClient();
    }
}
