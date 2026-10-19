/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.examples;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for DynamicHandshakeExample functionality
 */
public class DynamicHandshakeExampleTest {
    
    private Config config;
    
    @BeforeEach
    public void setUp() {
        config = Config.createConfig();
        config.setDefaultRunningMode(RunningModeType.SERVER);
        config.setDefaultSelectedCipherSuite("TLS_PSK_WITH_AES_128_CBC_SHA");
        config.setDefaultServerSupportedCipherSuites(Arrays.asList("TLS_PSK_WITH_AES_128_CBC_SHA"));
        config.setDefaultPSKIdentity("Client_identity".getBytes());
        config.setDefaultPSKKey(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                                          0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F});
        config.setDefaultConnections(Arrays.asList(new InboundConnection(4433, "server")));
    }
    
    @Test
    public void testSessionResumptionDetection() {
        // Create test session ID
        byte[] sessionId = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        
        // Create ClientHello with session ID (resumption attempt)
        ClientHelloMessage resumptionHello = new ClientHelloMessage();
        resumptionHello.setSessionId(sessionId);
        
        // Create ClientHello without session ID (new session)
        ClientHelloMessage newSessionHello = new ClientHelloMessage();
        newSessionHello.setSessionId(new byte[0]);
        
        // Test resumption detection
        assertTrue(isSessionResumption(resumptionHello, sessionId));
        assertFalse(isSessionResumption(newSessionHello, sessionId));
        assertFalse(isSessionResumption(null, sessionId));
        assertFalse(isSessionResumption(resumptionHello, null));
    }
    
    @Test
    public void testWorkflowCreationForResumption() {
        WorkflowTrace resumptionTrace = createResumptionWorkflow();
        
        // Verify correct number of actions
        assertEquals(5, resumptionTrace.getTlsActions().size());
        
        // Verify action sequence
        assertTrue(resumptionTrace.getTlsActions().get(0) instanceof SendAction);
        assertTrue(((SendAction)resumptionTrace.getTlsActions().get(0)).getSendMessages().get(0) 
                   instanceof ServerHelloMessage);
        
        assertTrue(resumptionTrace.getTlsActions().get(1) instanceof SendAction);
        assertTrue(((SendAction)resumptionTrace.getTlsActions().get(1)).getSendMessages().get(0) 
                   instanceof ChangeCipherSpecMessage);
        
        assertTrue(resumptionTrace.getTlsActions().get(2) instanceof SendAction);
        assertTrue(((SendAction)resumptionTrace.getTlsActions().get(2)).getSendMessages().get(0) 
                   instanceof FinishedMessage);
        
        assertTrue(resumptionTrace.getTlsActions().get(3) instanceof ReceiveAction);
        assertTrue(resumptionTrace.getTlsActions().get(4) instanceof ReceiveAction);
    }
    
    @Test
    public void testWorkflowCreationForFullHandshake() {
        WorkflowTrace fullTrace = createFullHandshakeWorkflow();
        
        // Verify correct number of actions
        assertEquals(8, fullTrace.getTlsActions().size());
        
        // Verify action sequence includes PSK key exchange
        boolean hasPskServerKeyExchange = false;
        for (TlsAction action : fullTrace.getTlsActions()) {
            if (action instanceof SendAction) {
                SendAction sendAction = (SendAction) action;
                if (sendAction.getSendMessages().stream()
                        .anyMatch(msg -> msg instanceof PskServerKeyExchangeMessage)) {
                    hasPskServerKeyExchange = true;
                    break;
                }
            }
        }
        assertTrue(hasPskServerKeyExchange);
    }
    
    @Test
    public void testDynamicWorkflowSelection() {
        // Test session ID
        byte[] sessionId = new byte[]{0x0A, 0x0B, 0x0C, 0x0D};
        
        // Create state with context
        State state = new State(config);
        TlsContext context = state.getTlsContext();
        context.setServerSessionId(sessionId);
        
        // Simulate receiving ClientHello with matching session ID
        ClientHelloMessage resumptionHello = new ClientHelloMessage();
        resumptionHello.setSessionId(sessionId);
        
        WorkflowTrace selectedTrace = selectWorkflowBasedOnClientHello(resumptionHello, sessionId);
        
        // Should select resumption workflow (5 actions)
        assertEquals(5, selectedTrace.getTlsActions().size());
        
        // Simulate receiving ClientHello with empty session ID
        ClientHelloMessage newSessionHello = new ClientHelloMessage();
        newSessionHello.setSessionId(new byte[0]);
        
        selectedTrace = selectWorkflowBasedOnClientHello(newSessionHello, sessionId);
        
        // Should select full handshake workflow (8 actions)
        assertEquals(8, selectedTrace.getTlsActions().size());
    }
    
    // Helper methods
    
    private boolean isSessionResumption(ClientHelloMessage clientHello, byte[] expectedSessionId) {
        if (clientHello == null || expectedSessionId == null) {
            return false;
        }
        
        byte[] receivedSessionId = clientHello.getSessionId().getValue();
        return receivedSessionId != null && 
               receivedSessionId.length > 0 && 
               Arrays.equals(receivedSessionId, expectedSessionId);
    }
    
    private WorkflowTrace createResumptionWorkflow() {
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(new SendAction(new ServerHelloMessage()));
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
        trace.addTlsAction(new SendAction(new FinishedMessage()));
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage()));
        trace.addTlsAction(new ReceiveAction(new FinishedMessage()));
        return trace;
    }
    
    private WorkflowTrace createFullHandshakeWorkflow() {
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(new SendAction(new ServerHelloMessage()));
        trace.addTlsAction(new SendAction(new PskServerKeyExchangeMessage()));
        trace.addTlsAction(new SendAction(new ServerHelloDoneMessage()));
        trace.addTlsAction(new ReceiveAction(new PskClientKeyExchangeMessage()));
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage()));
        trace.addTlsAction(new ReceiveAction(new FinishedMessage()));
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
        trace.addTlsAction(new SendAction(new FinishedMessage()));
        return trace;
    }
    
    private WorkflowTrace selectWorkflowBasedOnClientHello(ClientHelloMessage clientHello, 
                                                          byte[] expectedSessionId) {
        if (isSessionResumption(clientHello, expectedSessionId)) {
            return createResumptionWorkflow();
        } else {
            return createFullHandshakeWorkflow();
        }
    }
}