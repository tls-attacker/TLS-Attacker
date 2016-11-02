/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.testtls.impl;

import de.rub.nds.tlsattacker.testtls.config.TestServerConfig;
import de.rub.nds.tlsattacker.testtls.policy.TlsPeerProperties;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.protocol.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.MessageActionFactory;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class CipherSuiteOrderTest extends HandshakeTest {

    private boolean serverSupportsCipherSuitePreference;

    private final Set<CipherSuite> supportedCipherSuites;

    private ProtocolVersion currentProtocolVersion;

    public CipherSuiteOrderTest(ConfigHandler configHandler, TestServerConfig serverConfig) {
        super(configHandler, serverConfig);
        supportedCipherSuites = new HashSet<>();
    }

    @Override
    public void startTests() {
        collectCipherSuites();
        if (supportedCipherSuites.size() > 1) {
            try {
                List<CipherSuite> list = new ArrayList<>(supportedCipherSuites);
                serverConfig.setCipherSuites(list);
                serverConfig.setProtocolVersion(currentProtocolVersion);
                CipherSuite cs1 = getSelectedCipherSuite();
                Collections.reverse(list);
                serverConfig.setCipherSuites(list);
                CipherSuite cs2 = getSelectedCipherSuite();
                if(cs2 == cs1) {
                    serverSupportsCipherSuitePreference = true;
                }
            } catch (Exception ex) {
                LOGGER.info(ex.getLocalizedMessage());
                LOGGER.debug(ex.getLocalizedMessage(), ex);
                result = "\n Server cipher suite selection cannot be recognized";
            }
            result = "\n Server uses own cipher suite preferences: " + serverSupportsCipherSuitePreference;
        } else {
            result = "\n Server cipher suite selection cannot be recognized (lees than 2 cipher suites compatible)";
        }
    }

    private void collectCipherSuites() {
        for (ProtocolVersion pv : ProtocolVersion.values()) {
            if (pv == ProtocolVersion.DTLS10 || pv == ProtocolVersion.DTLS12) {
                continue;
            }
            currentProtocolVersion = pv;
            for (CipherSuite cs : CipherSuite.values()) {
                serverConfig.setProtocolVersion(pv);
                serverConfig.setCipherSuites(Collections.singletonList(cs));
                boolean success = false;
                try {
                    success = executeHandshake();
                } catch (Exception ex) {
                    LOGGER.info(ex.getLocalizedMessage());
                    LOGGER.debug(ex.getLocalizedMessage(), ex);
                }
                if (success) {
                    supportedCipherSuites.add(cs);
                    if (supportedCipherSuites.size() > 1) {
                        return;
                    }
                }
            }
        }
    }
    
    CipherSuite getSelectedCipherSuite() {
        TransportHandler transportHandler = configHandler.initializeTransportHandler(serverConfig);
        TlsContext tlsContext = configHandler.initializeTlsContext(serverConfig);
        tlsContext.setProtocolVersion(serverConfig.getProtocolVersion());
        tlsContext.setSelectedCipherSuite(serverConfig.getCipherSuites().get(0));
        WorkflowTrace workflowTrace = new WorkflowTrace();
        ClientHelloMessage ch = new ClientHelloMessage();
        workflowTrace.add(MessageActionFactory.createAction(ConnectionEnd.CLIENT, ConnectionEnd.CLIENT, ch));
        workflowTrace.add(MessageActionFactory.createAction(ConnectionEnd.CLIENT, ConnectionEnd.SERVER, new ArbitraryMessage()));
        ch.setSupportedCipherSuites(serverConfig.getCipherSuites());
        ch.setSupportedCompressionMethods(serverConfig.getCompressionMethods());
        WorkflowConfigurationFactory.initializeClientHelloExtensions(serverConfig, ch);
        tlsContext.setWorkflowTrace(workflowTrace);
        WorkflowConfigurationFactory.initializeProtocolMessageOrder(tlsContext);
        WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);
        workflowExecutor.executeWorkflow();
        transportHandler.closeConnection();
        if(workflowTrace.getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.SERVER_HELLO) != null) {
            ServerHelloMessage shm = (ServerHelloMessage) workflowTrace.getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.SERVER_HELLO);
            return CipherSuite.getCipherSuite(shm.getSelectedCipherSuite().getValue());
        }
        throw new ConfigurationException("No ServerHello message found");
    }

    @Override
    public void fillTlsPeerProperties(TlsPeerProperties properties) {
        properties.setUsingCiphersuitePreferenes(serverSupportsCipherSuitePreference);
    }
}
