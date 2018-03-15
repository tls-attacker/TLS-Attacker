/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.docker;

import de.rub.nds.tls.subject.TlsServer;
import de.rub.nds.tls.subject.docker.DockerSpotifyTlsServerManager;
import de.rub.nds.tls.subject.docker.DockerTlsServerManagerFactory;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import de.rub.nds.tlsattacker.util.tests.DockerTests;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(DockerTests.class)
public class DockerHandshakeIT {

    private static TlsServer server;

    @BeforeClass
    public static void setUp() {
        System.out.println("Trying to initialize DockerTests");
        UnlimitedStrengthEnabler.enable();
        Security.addProvider(new BouncyCastleProvider());
        DockerSpotifyTlsServerManager serverManager = DockerTlsServerManagerFactory
                .get(DockerTlsServerManagerFactory.DockerTlsServerType.OPENSSL);
        server = serverManager.getTlsServer();
        System.out.println("Started the Docker server at:" + server.host + ":" + server.port);
    }

    @AfterClass
    public static void tearDown() {
        // System.out.println(server.getServerLogs());
        server.kill();
    }

    @Test
    public void testTls10ClientHandshakes() {
        List<CipherSuite> suiteList = new LinkedList<>();
        suiteList.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        suiteList.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
        suiteList.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
        suiteList.add(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
        suiteList.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
        suiteList.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
        for (CipherSuite suite : suiteList) {
            Config config = Config.createConfig();
            if (AlgorithmResolver.getKeyExchangeAlgorithm(suite).isEC()) {
                config.setAddECPointFormatExtension(Boolean.TRUE);
                config.setAddEllipticCurveExtension(Boolean.TRUE);
            } else {
                config.setAddECPointFormatExtension(Boolean.FALSE);
                config.setAddEllipticCurveExtension(Boolean.FALSE);
            }
            config.setDefaultClientSupportedCiphersuites(suite);
            config.setDefaultSelectedCipherSuite(suite);
            config.setHighestProtocolVersion(ProtocolVersion.TLS10);
            config.setSupportedVersions(ProtocolVersion.TLS10);
            config.getDefaultClientConnection().setHostname(server.host);
            config.getDefaultClientConnection().setPort(server.port);
            // config.setEnforceSettings(Boolean.TRUE);
            State state = new State(config);
            WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
            try {
                executor.executeWorkflow();
            } catch (Exception E) {
                E.printStackTrace();
                Assert.fail("Could not execute workflow with openssl: " + suite + ":TLS10");
            }
            if (state.getWorkflowTrace().executedAsPlanned()) {
                System.out.println("Could execute Handshake with openssl: " + suite + ":TLS10");
            } else {
                System.out.println(state.getWorkflowTrace().toString());
                System.out.println(server.getServerLogs());
                Assert.fail("Handshake did not execute as expected: " + suite + ":TLS10");
            }
        }

    }

    @Test
    public void testTls11ClientHandshakes() {
        List<CipherSuite> suiteList = new LinkedList<>();
        suiteList.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        suiteList.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
        suiteList.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
        suiteList.add(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
        suiteList.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
        suiteList.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
        for (CipherSuite suite : suiteList) {
            Config config = Config.createConfig();
            if (AlgorithmResolver.getKeyExchangeAlgorithm(suite).isEC()) {
                config.setAddECPointFormatExtension(Boolean.TRUE);
                config.setAddEllipticCurveExtension(Boolean.TRUE);
            } else {
                config.setAddECPointFormatExtension(Boolean.FALSE);
                config.setAddEllipticCurveExtension(Boolean.FALSE);
            }
            config.setDefaultClientSupportedCiphersuites(suite);
            config.setDefaultSelectedCipherSuite(suite);
            config.setHighestProtocolVersion(ProtocolVersion.TLS11);
            config.setSupportedVersions(ProtocolVersion.TLS11);
            config.getDefaultClientConnection().setHostname(server.host);
            config.getDefaultClientConnection().setPort(server.port);
            // config.setEnforceSettings(Boolean.TRUE);
            State state = new State(config);
            WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
            try {
                executor.executeWorkflow();
            } catch (Exception E) {
                E.printStackTrace();
                Assert.fail("Could not execute workflow with openssl: " + suite + ":TLS11");
            }
            if (state.getWorkflowTrace().executedAsPlanned()) {
                System.out.println("Could execute Handshake with openssl: " + suite + ":TLS11");
            } else {
                System.out.println(state.getWorkflowTrace().toString());
                System.out.println(server.getServerLogs());
                Assert.fail("Handshake did not execute as expected: " + suite + ":TLS11");
            }

        }
    }

    @Test
    public void testTls12ClientHandshakes() {
        List<CipherSuite> suiteList = new LinkedList<>();
        suiteList.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        suiteList.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
        suiteList.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
        suiteList.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256);
        suiteList.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
        suiteList.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256);
        suiteList.add(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
        suiteList.add(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256);
        suiteList.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
        suiteList.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
        suiteList.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
        suiteList.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384);
        suiteList.add(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        suiteList.add(CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384);
        suiteList.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
        suiteList.add(CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
        suiteList.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        suiteList.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
        for (CipherSuite suite : suiteList) {
            Config config = Config.createConfig();
            if (AlgorithmResolver.getKeyExchangeAlgorithm(suite).isEC()) {
                config.setAddECPointFormatExtension(Boolean.TRUE);
                config.setAddEllipticCurveExtension(Boolean.TRUE);
            } else {
                config.setAddECPointFormatExtension(Boolean.FALSE);
                config.setAddEllipticCurveExtension(Boolean.FALSE);
            }
            config.setDefaultClientSupportedCiphersuites(suite);
            config.setDefaultSelectedCipherSuite(suite);
            config.setHighestProtocolVersion(ProtocolVersion.TLS12);
            config.setSupportedVersions(ProtocolVersion.TLS12);
            config.getDefaultClientConnection().setHostname(server.host);
            config.getDefaultClientConnection().setPort(server.port);
            // config.setEnforceSettings(Boolean.TRUE);
            State state = new State(config);
            WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
            try {
                executor.executeWorkflow();
            } catch (Exception E) {
                E.printStackTrace();
                Assert.fail("Could not execute workflow with openssl: " + suite + ":" + ProtocolVersion.TLS12);

            }
            if (state.getWorkflowTrace().executedAsPlanned()) {
                System.out.println("Could execute Handshake with openssl: " + suite + ":" + ProtocolVersion.TLS12);
            } else {
                System.out.println(state.getWorkflowTrace().toString());
                System.out.println(server.getServerLogs());
                Assert.fail("Handshake did not execute as expected: " + suite + ":" + ProtocolVersion.TLS12);
            }

        }
    }

    // @Test
    // public void testRC4ClientHandshakes() {
    // List<ProtocolVersion> versionList = new LinkedList<>();
    // versionList.add(ProtocolVersion.TLS10);
    // versionList.add(ProtocolVersion.TLS11);
    // versionList.add(ProtocolVersion.TLS12);
    // List<CipherSuite> suiteList = new LinkedList<>();
    // suiteList.add(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
    // suiteList.add(CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA);
    // for (ProtocolVersion version : versionList) {
    // for (CipherSuite suite : suiteList) {
    // Config config = Config.createConfig();
    // config.setDefaultClientSupportedCiphersuites(suite);
    // config.setDefaultSelectedCipherSuite(suite);
    // config.setHighestProtocolVersion(version);
    // config.setSupportedVersions(version);
    // config.getDefaultClientConnection().setHostname(server.host);
    // config.getDefaultClientConnection().setPort(server.port);
    // State state = new State(config);
    // WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
    // try {
    // executor.executeWorkflow();
    // } catch (Exception E) {
    // E.printStackTrace();
    // Assert.fail("Could not execute workflow with openssl: " + suite + ":" +
    // version);
    // }
    // if (state.getWorkflowTrace().executedAsPlanned()) {
    // System.out.println("Could execute Handshake with openssl: " + suite + ":"
    // + version);
    // } else {
    // System.out.println(state.getWorkflowTrace().toString());
    // Assert.fail("Handshake did not execute as expected: " + suite + ":" +
    // version);
    // }
    // }
    // }
    // }
}
