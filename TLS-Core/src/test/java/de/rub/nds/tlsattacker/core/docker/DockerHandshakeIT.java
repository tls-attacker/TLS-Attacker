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
import de.rub.nds.tls.subject.TlsServerManager;
import de.rub.nds.tls.subject.docker.DockerSpotifyTlsServerManager;
import de.rub.nds.tls.subject.docker.DockerTlsServerManagerFactory;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.config.Configurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class DockerHandshakeIT {

    private TlsServer server;

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        DockerSpotifyTlsServerManager serverManager = DockerTlsServerManagerFactory
                .get(DockerTlsServerManagerFactory.DockerTlsServerType.OPENSSL);
        server = serverManager.getTlsServer();
    }

    @After
    public void tearDown() {
        //    System.out.println(server.getServerLogs());
        server.kill();
    }

    @Test
    public void testClientHandshakes() {
        List<ProtocolVersion> versionList = new LinkedList<>();
        versionList.add(ProtocolVersion.TLS12);
        versionList.add(ProtocolVersion.TLS11);
        versionList.add(ProtocolVersion.TLS10);
        List<CipherSuite> suiteList = new LinkedList<>();
        suiteList.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        suiteList.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
        suiteList.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
        for (ProtocolVersion version : versionList) {
            for (CipherSuite suite : suiteList) {
                Config config = Config.createConfig();
                config.setDefaultClientSupportedCiphersuites(suite);
                config.setDefaultSelectedCipherSuite(suite);
                config.setHighestProtocolVersion(version);
                config.setSupportedVersions(version);
                config.getDefaultClientConnection().setHostname(server.host);
                config.getDefaultClientConnection().setPort(server.port);
                config.setEnforceSettings(Boolean.TRUE);
                State state = new State(config);
                WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
                try {
                    executor.executeWorkflow();
                } catch (Exception E) {
                    E.printStackTrace();
                    Assert.fail("Could not execute workflow with openssl: " + suite + ":" + version);
                }
                if (state.getWorkflowTrace().executedAsPlanned()) {
                    System.out.println("Could execute Handshake with openssl: " + suite + ":" + version);
                } else {
                    System.out.println(state.getWorkflowTrace().toString());
                    Assert.fail("Handshake did not execute as expected: " + suite + ":" + version);
                }
            }
        }
    }

    @Test
    public void testServerGCMHandshakes() {
        List<ProtocolVersion> versionList = new LinkedList<>();
        versionList.add(ProtocolVersion.TLS12);
        // versionList.add(ProtocolVersion.TLS11);
        List<CipherSuite> suiteList = new LinkedList<>();
        suiteList.add(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        suiteList.add(CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384);
        for (ProtocolVersion version : versionList) {
            for (CipherSuite suite : suiteList) {
                Config config = Config.createConfig();
                config.setDefaultClientSupportedCiphersuites(suite);
                config.setDefaultSelectedCipherSuite(suite);
                config.setHighestProtocolVersion(version);
                config.setSupportedVersions(version);
                config.getDefaultClientConnection().setHostname(server.host);
                config.getDefaultClientConnection().setPort(server.port);
                config.setDefaulRunningMode(RunningModeType.CLIENT);
                State state = new State(config);
                WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
                try {
                    executor.executeWorkflow();
                } catch (Exception E) {
                    E.printStackTrace();
                    Assert.fail("Could not execute workflow with openssl: " + suite + ":" + version);
                }
                if (state.getWorkflowTrace().executedAsPlanned()) {
                    System.out.println("Could execute Handshake with openssl: " + suite + ":" + version);
                } else {
                    System.out.println(state.getWorkflowTrace().toString());
                    Assert.fail("Handshake did not execute as expected: " + suite + ":" + version);
                }
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
