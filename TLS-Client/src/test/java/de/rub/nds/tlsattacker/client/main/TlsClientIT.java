/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.client.main;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import de.rub.nds.modifiablevariable.util.BadRandom;
import de.rub.nds.tlsattacker.client.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.TimeoutDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.util.BasicTlsServer;
import de.rub.nds.tlsattacker.core.util.KeyStoreGenerator;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.util.FixedTimeProvider;
import de.rub.nds.tlsattacker.util.TimeHelper;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

public class TlsClientIT {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final int TIMEOUT = 2000;

    private final BadRandom random = new BadRandom(new Random(0), null);

    private BasicTlsServer tlsServer;

    @AfterEach
    public void tearDown() {
        tlsServer.shutdown();
    }

    @ParameterizedTest
    @EnumSource(
            value = ProtocolVersion.class,
            names = {"SSL3", "TLS10", "TLS11", "TLS12"})
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testTlsClientWithRsaForProtocolVersion(ProtocolVersion protocolVersion)
            throws UnrecoverableKeyException,
                    CertificateException,
                    KeyStoreException,
                    IOException,
                    NoSuchAlgorithmException,
                    SignatureException,
                    InvalidKeyException,
                    NoSuchProviderException,
                    OperatorCreationException,
                    KeyManagementException {
        startBasicTlsServer(X509PublicKeyType.RSA);
        assumeTrue(
                tlsServer.getEnabledProtocolVersions().contains(protocolVersion),
                "The TLS server used for testing does not support the protocol version to test, all supported versions: "
                        + tlsServer.getEnabledProtocolVersions()
                        + ". Are you using a newer JDK which has SSL3, TLSv1.0, and TLSv1.1 disabled by default?");
        Config config = createAttackerConfig(protocolVersion, tlsServer.getPort());
        List<CipherSuite> testableCipherSuites =
                CipherSuite.getImplemented().stream()
                        .filter(
                                cs ->
                                        isCipherSuiteTestable(
                                                KeyExchangeAlgorithm.RSA,
                                                config,
                                                cs,
                                                List.of(tlsServer.getCipherSuites())))
                        .collect(Collectors.toList());
        for (CipherSuite suite : testableCipherSuites) {
            System.out.println(suite);
        }
        assertAll(
                testableCipherSuites.stream()
                        .map(cs -> () -> executeHandshakeWorkflowWithCipherSuite(config, cs)));
    }

    @ParameterizedTest
    @EnumSource(
            value = ProtocolVersion.class,
            names = {"SSL3", "TLS10", "TLS11", "TLS12"})
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testTlsClientWithEcForProtocolVersion(ProtocolVersion protocolVersion)
            throws OperatorCreationException,
                    UnrecoverableKeyException,
                    CertificateException,
                    KeyStoreException,
                    IOException,
                    NoSuchAlgorithmException,
                    SignatureException,
                    InvalidKeyException,
                    NoSuchProviderException,
                    KeyManagementException {
        startBasicTlsServer(X509PublicKeyType.ECDH_ECDSA);
        assumeTrue(
                tlsServer.getEnabledProtocolVersions().contains(protocolVersion),
                "The TLS server used for testing does not support the protocol version to test, all supported versions: "
                        + tlsServer.getEnabledProtocolVersions()
                        + ". Are you using a newer JDK which has SSL3, TLSv1.0, and TLSv1.1 disabled by default?");
        Config config = createAttackerConfig(protocolVersion, tlsServer.getPort());
        List<CipherSuite> testableCipherSuites =
                CipherSuite.getImplemented().stream()
                        .filter(
                                cs ->
                                        isCipherSuiteTestable(
                                                KeyExchangeAlgorithm.ECDHE_ECDSA,
                                                config,
                                                cs,
                                                List.of(tlsServer.getCipherSuites())))
                        .collect(Collectors.toList());
        assertAll(
                testableCipherSuites.stream()
                        .map(cs -> () -> executeHandshakeWorkflowWithCipherSuite(config, cs)));
    }

    public void startBasicTlsServer(X509PublicKeyType x509PublicKeyType)
            throws UnrecoverableKeyException,
                    CertificateException,
                    KeyStoreException,
                    IOException,
                    NoSuchAlgorithmException,
                    KeyManagementException,
                    SignatureException,
                    InvalidKeyException,
                    NoSuchProviderException,
                    OperatorCreationException {
        TimeHelper.setProvider(new FixedTimeProvider(0));
        KeyPair k = null;
        switch (x509PublicKeyType) {
            case RSA:
                k = KeyStoreGenerator.createRSAKeyPair(1024, random);
                break;
            case ECDH_ECDSA:
                k = KeyStoreGenerator.createECKeyPair(256, random);
                break;
            default:
                fail(
                        "Unable to start basic TLS server for public key algorithm "
                                + x509PublicKeyType);
        }
        KeyStore ks = KeyStoreGenerator.createKeyStore(k, random);
        tlsServer = new BasicTlsServer(ks, KeyStoreGenerator.PASSWORD, "TLS", 0);
        tlsServer.start();
        while (!tlsServer.isInitialized())
            ;
    }

    public Config createAttackerConfig(ProtocolVersion protocolVersion, int serverPort) {
        ClientCommandConfig clientCommandConfig = new ClientCommandConfig(new GeneralDelegate());
        TimeoutDelegate timeoutDelegate = clientCommandConfig.getDelegate(TimeoutDelegate.class);
        timeoutDelegate.setTimeout(TIMEOUT);
        ClientDelegate clientDelegate = clientCommandConfig.getDelegate(ClientDelegate.class);
        clientDelegate.setHost("localhost:" + serverPort);
        Config config = clientCommandConfig.createConfig();
        config.setEnforceSettings(false);
        config.setHighestProtocolVersion(protocolVersion);
        return config;
    }

    private boolean isCipherSuiteTestable(
            KeyExchangeAlgorithm keyExchangeAlgorithm,
            Config config,
            CipherSuite cs,
            List<String> serverSupportedCipherSuites) {
        if (cs.name().toUpperCase().contains("NULL") || cs.name().toUpperCase().contains("ANON")) {
            return false;
        }
        KeyExchangeAlgorithm kex = cs.getKeyExchangeAlgorithm();

        final boolean serverSupportsCipherSuite =
                serverSupportedCipherSuites.contains(cs.toString());
        final boolean cipherSuiteIsSupportedByProtocolVersion =
                cs.isSupportedInProtocol(config.getHighestProtocolVersion());
        return serverSupportsCipherSuite
                && cipherSuiteIsSupportedByProtocolVersion
                && kex == keyExchangeAlgorithm;
    }

    private void executeHandshakeWorkflowWithCipherSuite(Config config, CipherSuite cs) {
        LOGGER.info(
                "Executing handshake workflow - Protocol version: {}\t Cipher suite: {}",
                config.getHighestProtocolVersion(),
                cs);
        config.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
        config.setDefaultClientSupportedCipherSuites(cs);
        config.setDefaultSelectedCipherSuite(cs);
        State state = new State(config);

        WorkflowExecutor workflowExecutor =
                WorkflowExecutorFactory.createWorkflowExecutor(
                        config.getWorkflowExecutorType(), state);

        assertDoesNotThrow(workflowExecutor::executeWorkflow);
        assertTrue(
                state.getWorkflowTrace().executedAsPlanned(), state.getWorkflowTrace().toString());
    }
}
