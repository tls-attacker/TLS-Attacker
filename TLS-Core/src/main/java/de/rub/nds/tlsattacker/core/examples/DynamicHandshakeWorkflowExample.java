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
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import java.io.IOException;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Advanced example showing how to use WorkflowExecutor with conditional execution
 * for handling both session resumption and full handshake scenarios.
 * 
 * This example provides a more integrated approach using the WorkflowExecutor
 * while still maintaining the ability to handle different handshake paths.
 */
public class DynamicHandshakeWorkflowExample {
    
    private static final Logger LOGGER = LogManager.getLogger();
    
    public static void main(String[] args) {
        // Create initial configuration
        Config config = createServerConfig();
        
        try {
            // Execute initial full handshake
            byte[] sessionId = executeInitialHandshake(config);
            LOGGER.info("Initial handshake completed. Session ID: {}", bytesToHex(sessionId));
            
            // Handle subsequent connections with dynamic workflow
            handleDynamicConnection(config, sessionId);
            
        } catch (Exception e) {
            LOGGER.error("Error during execution", e);
        }
    }
    
    /**
     * Creates server configuration for PSK handshakes
     */
    private static Config createServerConfig() {
        Config config = Config.createConfig();
        config.setDefaultRunningMode(RunningModeType.SERVER);
        
        // Configure PSK
        config.setDefaultSelectedCipherSuite("TLS_PSK_WITH_AES_128_CBC_SHA");
        config.setDefaultServerSupportedCipherSuites(Arrays.asList("TLS_PSK_WITH_AES_128_CBC_SHA"));
        config.setDefaultPSKIdentity("Client_identity".getBytes());
        config.setDefaultPSKKey(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                                          0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F});
        
        // Configure connection
        config.setDefaultConnections(Arrays.asList(new InboundConnection(4433, "server")));
        
        return config;
    }
    
    /**
     * Executes initial full handshake using WorkflowExecutor
     */
    private static byte[] executeInitialHandshake(Config config) throws WorkflowExecutionException {
        // Create workflow trace for initial handshake
        WorkflowTrace trace = new WorkflowTrace();
        
        // Initial handshake flow
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new HelloVerifyRequestMessage()));
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        trace.addTlsAction(new SendAction(new ServerHelloMessage()));
        trace.addTlsAction(new SendAction(new PskServerKeyExchangeMessage()));
        trace.addTlsAction(new SendAction(new ServerHelloDoneMessage()));
        trace.addTlsAction(new ReceiveAction(new PskClientKeyExchangeMessage()));
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage()));
        trace.addTlsAction(new ReceiveAction(new FinishedMessage()));
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
        trace.addTlsAction(new SendAction(new FinishedMessage()));
        trace.addTlsAction(new ReceiveAction(new AlertMessage()));
        trace.addTlsAction(new ResetConnectionAction());
        
        // Execute workflow
        State state = new State(config, trace);
        DefaultWorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        executor.executeWorkflow();
        
        return state.getTlsContext().getServerSessionId();
    }
    
    /**
     * Handles subsequent connection with dynamic workflow based on session ID
     */
    private static void handleDynamicConnection(Config config, byte[] expectedSessionId) 
            throws WorkflowExecutionException, IOException {
        
        // Create partial workflow up to the decision point
        WorkflowTrace initialTrace = new WorkflowTrace();
        initialTrace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        initialTrace.addTlsAction(new SendAction(new HelloVerifyRequestMessage()));
        initialTrace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        
        State state = new State(config, initialTrace);
        
        // Execute up to the point where we need to check session ID
        executeActionsUntilDecisionPoint(state);
        
        // Determine handshake type based on received ClientHello
        ClientHelloMessage clientHello = findLastClientHello(state);
        boolean isResumption = checkSessionResumption(clientHello, expectedSessionId);
        
        // Create appropriate workflow continuation
        WorkflowTrace continuationTrace = createContinuationWorkflow(isResumption);
        
        // Add continuation actions to state and execute
        for (TlsAction action : continuationTrace.getTlsActions()) {
            state.getWorkflowTrace().addTlsAction(action);
        }
        
        // Continue execution
        DefaultWorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        executor.executeWorkflow();
        
        LOGGER.info("Dynamic handshake completed. Type: {}", 
                    isResumption ? "Session Resumption" : "Full Handshake");
    }
    
    /**
     * Executes actions up to the decision point
     */
    private static void executeActionsUntilDecisionPoint(State state) 
            throws WorkflowExecutionException, IOException {
        
        for (TlsAction action : state.getWorkflowTrace().getTlsActions()) {
            if (!action.isExecuted()) {
                action.setConnectionAlias(state.getTlsContext().getConnection().getAlias());
                action.normalize();
                action.execute(state);
                
                if (!action.executedAsPlanned()) {
                    LOGGER.warn("Action did not execute as planned: {}", 
                                action.getClass().getSimpleName());
                }
            }
        }
    }
    
    /**
     * Finds the last received ClientHello message
     */
    private static ClientHelloMessage findLastClientHello(State state) {
        for (int i = state.getWorkflowTrace().getTlsActions().size() - 1; i >= 0; i--) {
            TlsAction action = state.getWorkflowTrace().getTlsActions().get(i);
            if (action instanceof ReceiveAction) {
                ReceiveAction receiveAction = (ReceiveAction) action;
                for (ProtocolMessage msg : receiveAction.getReceivedMessages()) {
                    if (msg instanceof ClientHelloMessage) {
                        return (ClientHelloMessage) msg;
                    }
                }
            }
        }
        return null;
    }
    
    /**
     * Checks if the ClientHello indicates session resumption
     */
    private static boolean checkSessionResumption(ClientHelloMessage clientHello, 
                                                 byte[] expectedSessionId) {
        if (clientHello == null || expectedSessionId == null) {
            return false;
        }
        
        byte[] receivedSessionId = clientHello.getSessionId().getValue();
        return receivedSessionId != null && 
               receivedSessionId.length > 0 && 
               Arrays.equals(receivedSessionId, expectedSessionId);
    }
    
    /**
     * Creates continuation workflow based on handshake type
     */
    private static WorkflowTrace createContinuationWorkflow(boolean isResumption) {
        WorkflowTrace trace = new WorkflowTrace();
        
        if (isResumption) {
            // Session resumption flow
            trace.addTlsAction(new SendAction(new ServerHelloMessage()));
            trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
            trace.addTlsAction(new SendAction(new FinishedMessage()));
            trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage()));
            trace.addTlsAction(new ReceiveAction(new FinishedMessage()));
        } else {
            // Full handshake flow
            trace.addTlsAction(new SendAction(new ServerHelloMessage()));
            trace.addTlsAction(new SendAction(new PskServerKeyExchangeMessage()));
            trace.addTlsAction(new SendAction(new ServerHelloDoneMessage()));
            trace.addTlsAction(new ReceiveAction(new PskClientKeyExchangeMessage()));
            trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage()));
            trace.addTlsAction(new ReceiveAction(new FinishedMessage()));
            trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
            trace.addTlsAction(new SendAction(new FinishedMessage()));
        }
        
        return trace;
    }
    
    /**
     * Helper method to convert bytes to hex string
     */
    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}