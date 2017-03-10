/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.testtls.impl;

import de.rub.nds.tlsattacker.main.TLSClient;
import de.rub.nds.tlsattacker.testtls.config.TestServerConfig;
import de.rub.nds.tlsattacker.testtls.policy.TlsPeerProperties;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.factory.WorkflowConfigurationFactory;
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
                TlsConfig tlsConfig = configHandler.initialize(serverConfig);
                List<CipherSuite> list = new ArrayList<>(supportedCipherSuites);
                tlsConfig.setSupportedCiphersuites(list);
                tlsConfig.setHighestProtocolVersion(currentProtocolVersion);
                CipherSuite cs1 = getSelectedCipherSuite(tlsConfig);
                Collections.reverse(list);
                tlsConfig = configHandler.initialize(serverConfig);
                tlsConfig.setSupportedCiphersuites(list);
                CipherSuite cs2 = getSelectedCipherSuite(tlsConfig);
                if (cs2 == cs1) {
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
                TlsConfig tlsConfig = configHandler.initialize(serverConfig);

                tlsConfig.setHighestProtocolVersion(pv);
                tlsConfig.setSupportedCiphersuites(Collections.singletonList(cs));
                boolean success = false;
                try {
                    success = executeHandshake(tlsConfig);
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

    CipherSuite getSelectedCipherSuite(TlsConfig tlsConfig) {
        WorkflowTrace workflowTrace = new WorkflowConfigurationFactory(tlsConfig).createHandshakeWorkflow();
        tlsConfig.setWorkflowTrace(workflowTrace);
        TLSClient client = new TLSClient();
        client.startTlsClient(tlsConfig);
        if (workflowTrace.getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.SERVER_HELLO) != null) {
            ServerHelloMessage shm = (ServerHelloMessage) workflowTrace
                    .getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.SERVER_HELLO);
            return CipherSuite.getCipherSuite(shm.getSelectedCipherSuite().getValue());
        }
        throw new ConfigurationException("No ServerHello message found");
    }

    @Override
    public void fillTlsPeerProperties(TlsPeerProperties properties) {
        properties.setUsingCiphersuitePreferenes(serverSupportsCipherSuitePreference);
    }
}
