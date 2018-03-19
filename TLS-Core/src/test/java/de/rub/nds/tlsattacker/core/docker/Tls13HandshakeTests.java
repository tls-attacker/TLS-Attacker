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
import de.rub.nds.tls.subject.docker.DockerTlsServerType;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import de.rub.nds.tlsattacker.util.tests.DockerTests;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(DockerTests.class)
public class Tls13HandshakeTests {

    public Tls13HandshakeTests() {
    }

    private DockerSpotifyTlsServerManager serverManager;
    private TlsServer server = null;

    @BeforeClass
    public static void setUpClass() {
        UnlimitedStrengthEnabler.enable();
        Security.addProvider(new BouncyCastleProvider());
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
        serverManager = DockerTlsServerManagerFactory.get(DockerTlsServerType.OPENSSL, "1.1.1-pre2");
        server = serverManager.getTlsServer();
    }

    @After
    public void tearDown() {
        if (server != null) {
            server.kill();
        }
    }

    @Test
    public void testTls13() {
        Config config = Config.createConfig();

        config.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
        config.setDefaultClientSupportedCiphersuites(CipherSuite.TLS_AES_128_GCM_SHA256);
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        config.setHighestProtocolVersion(ProtocolVersion.TLS13);
        config.setSupportedVersions(ProtocolVersion.TLS13_DRAFT22,ProtocolVersion.TLS13_DRAFT21, ProtocolVersion.TLS13_DRAFT20);
        config.getDefaultClientConnection().setHostname(server.host);
        config.getDefaultClientConnection().setPort(server.port);
        config.setSupportedSignatureAndHashAlgorithms(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA,
                HashAlgorithm.SHA256));
        config.setNamedCurves(NamedCurve.ECDH_X25519);
        config.setKeyShareType(NamedCurve.ECDH_X25519);
        config.setAddECPointFormatExtension(false);
        config.setAddEllipticCurveExtension(false);
        config.setAddSignatureAndHashAlgrorithmsExtension(true);
        config.setAddSupportedVersionsExtension(true);
        config.setAddKeyShareExtension(true);
        config.setUseRandomUnixTime(true);
        State state = new State(config);
        WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        try {
            executor.executeWorkflow();
        } catch (Exception E) {
            E.printStackTrace();
            Assert.fail("Could not execute workflow with openssl: " + this.toString());
        }
        if (state.getWorkflowTrace().executedAsPlanned()) {
            System.out.println("Could execute Handshake with openssl: " + this.toString());

        } else {
            System.out.println(state.getWorkflowTrace().toString());
            System.out.println(server.getServerLogs());
            Assert.fail("Handshake did not execute as expected: " + this.toString());
        }
    }

}
