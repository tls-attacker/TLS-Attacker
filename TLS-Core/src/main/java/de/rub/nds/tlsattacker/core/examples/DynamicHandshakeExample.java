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
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import java.io.IOException;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Example demonstrating how to handle both session resumption and full handshake
 * dynamically based on the ClientHello session ID.
 * 
 * This implementation addresses the issue described in #195 where TLS-Attacker needs
 * to support different handshake paths based on whether the client is attempting
 * session resumption or a new full handshake.
 */
public class DynamicHandshakeExample {
    
    private static final Logger LOGGER = LogManager.getLogger();
    
    public static void main(String[] args) {
        Config config = Config.createConfig();
        config.setDefaultRunningMode(RunningModeType.SERVER);
        
        // Configure for PSK as shown in the issue
        config.setDefaultSelectedCipherSuite("TLS_PSK_WITH_AES_128_CBC_SHA");
        config.setDefaultServerSupportedCipherSuites(Arrays.asList("TLS_PSK_WITH_AES_128_CBC_SHA"));
        
        // Add connection configuration
        config.setDefaultConnections(Arrays.asList(new InboundConnection(4433, "server")));
        
        try {
            // Execute first handshake
            State state = executeInitialHandshake(config);
            
            // Save session information
            byte[] sessionId = state.getTlsContext().getServerSessionId();
            LOGGER.info("Initial handshake completed. Session ID: {}", bytesToHex(sessionId));
            
            // Reset for second handshake
            state = new State(config);
            
            // Execute second handshake with dynamic path selection
            executeSecondHandshake(state, sessionId);
            
        } catch (Exception e) {
            LOGGER.error("Error during handshake execution", e);
        }
    }
    
    /**
     * Executes the initial full handshake
     */
    private static State executeInitialHandshake(Config config) throws WorkflowExecutionException, IOException {
        State state = new State(config);
        TlsContext context = state.getTlsContext();
        
        LOGGER.info("Starting initial full handshake...");
        
        // Execute initial handshake actions
        executeAction(new ReceiveAction(new ClientHelloMessage()), state);
        executeAction(new SendAction(new HelloVerifyRequestMessage()), state);
        executeAction(new ReceiveAction(new ClientHelloMessage()), state);
        executeAction(new SendAction(new ServerHelloMessage()), state);
        executeAction(new SendAction(new PskServerKeyExchangeMessage()), state);
        executeAction(new SendAction(new ServerHelloDoneMessage()), state);
        executeAction(new ReceiveAction(new PskClientKeyExchangeMessage()), state);
        executeAction(new ReceiveAction(new ChangeCipherSpecMessage()), state);
        executeAction(new ReceiveAction(new FinishedMessage()), state);
        executeAction(new SendAction(new ChangeCipherSpecMessage()), state);
        executeAction(new SendAction(new FinishedMessage()), state);
        executeAction(new ReceiveAction(new AlertMessage()), state);
        executeAction(new ResetConnectionAction(), state);
        
        return state;
    }
    
    /**
     * Executes the second handshake with dynamic path selection based on session ID
     */
    private static void executeSecondHandshake(State state, byte[] expectedSessionId) 
            throws WorkflowExecutionException, IOException {
        
        LOGGER.info("Starting second handshake...");
        
        // Receive first ClientHello
        ReceiveAction receiveClientHello = new ReceiveAction(new ClientHelloMessage());
        executeAction(receiveClientHello, state);
        
        // Check if ClientHello was received
        ClientHelloMessage clientHello = (ClientHelloMessage) receiveClientHello.getReceivedMessages().stream()
                .filter(msg -> msg instanceof ClientHelloMessage)
                .findFirst()
                .orElse(null);
        
        if (clientHello == null) {
            throw new WorkflowExecutionException("No ClientHello received");
        }
        
        // Send HelloVerifyRequest for DTLS (as shown in the issue example)
        executeAction(new SendAction(new HelloVerifyRequestMessage()), state);
        
        // Receive second ClientHello (after cookie verification)
        receiveClientHello = new ReceiveAction(new ClientHelloMessage());
        executeAction(receiveClientHello, state);
        
        clientHello = (ClientHelloMessage) receiveClientHello.getReceivedMessages().stream()
                .filter(msg -> msg instanceof ClientHelloMessage)
                .findFirst()
                .orElse(null);
        
        if (clientHello == null) {
            throw new WorkflowExecutionException("No second ClientHello received");
        }
        
        // Check session ID to determine handshake type
        byte[] receivedSessionId = clientHello.getSessionId().getValue();
        boolean isResumption = receivedSessionId != null && 
                               receivedSessionId.length > 0 && 
                               Arrays.equals(receivedSessionId, expectedSessionId);
        
        if (isResumption) {
            LOGGER.info("Session resumption detected. Executing abbreviated handshake...");
            executeResumptionHandshake(state);
        } else {
            LOGGER.info("New session detected. Executing full handshake...");
            executeFullHandshake(state);
        }
    }
    
    /**
     * Executes session resumption handshake
     */
    private static void executeResumptionHandshake(State state) 
            throws WorkflowExecutionException, IOException {
        
        // Session resumption flow
        executeAction(new SendAction(new ServerHelloMessage()), state);
        executeAction(new SendAction(new ChangeCipherSpecMessage()), state);
        executeAction(new SendAction(new FinishedMessage()), state);
        executeAction(new ReceiveAction(new ChangeCipherSpecMessage()), state);
        executeAction(new ReceiveAction(new FinishedMessage()), state);
        
        LOGGER.info("Session resumption handshake completed successfully");
    }
    
    /**
     * Executes full handshake
     */
    private static void executeFullHandshake(State state) 
            throws WorkflowExecutionException, IOException {
        
        // Full handshake flow
        executeAction(new SendAction(new ServerHelloMessage()), state);
        executeAction(new SendAction(new PskServerKeyExchangeMessage()), state);
        executeAction(new SendAction(new ServerHelloDoneMessage()), state);
        executeAction(new ReceiveAction(new PskClientKeyExchangeMessage()), state);
        executeAction(new ReceiveAction(new ChangeCipherSpecMessage()), state);
        executeAction(new ReceiveAction(new FinishedMessage()), state);
        executeAction(new SendAction(new ChangeCipherSpecMessage()), state);
        executeAction(new SendAction(new FinishedMessage()), state);
        
        LOGGER.info("Full handshake completed successfully");
    }
    
    /**
     * Helper method to execute a single action
     */
    private static void executeAction(TlsAction action, State state) 
            throws WorkflowExecutionException, IOException {
        
        action.setConnectionAlias(state.getTlsContext().getConnection().getAlias());
        action.normalize();
        action.execute(state);
        
        if (!action.executedAsPlanned()) {
            LOGGER.warn("Action did not execute as planned: {}", action.getClass().getSimpleName());
        }
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