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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
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
import java.util.Arrays;
import java.util.Collection;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@Category(DockerTests.class)
@RunWith(Parameterized.class)
public class Tls13HandshakeTests {

    private NamedGroup namedGroup;

    private SignatureAndHashAlgorithm signAlgorithm;

    private CipherSuite suite;

    private ProtocolVersion tls13Version;

    private DockerTlsServerType serverType;

    private String version;

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                { NamedGroup.ECDH_X25519,
                        new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA_PSS, HashAlgorithm.SHA256),
                        CipherSuite.TLS_AES_128_GCM_SHA256, ProtocolVersion.TLS13_DRAFT23, DockerTlsServerType.OPENSSL,
                        "1.1.1-pre2" },
                { NamedGroup.ECDH_X25519,
                        new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA_PSS, HashAlgorithm.SHA256),
                        CipherSuite.TLS_AES_256_GCM_SHA384, ProtocolVersion.TLS13_DRAFT23, DockerTlsServerType.OPENSSL,
                        "1.1.1-pre2" },
                { NamedGroup.SECP256R1,
                        new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA_PSS, HashAlgorithm.SHA256),
                        CipherSuite.TLS_AES_128_GCM_SHA256, ProtocolVersion.TLS13_DRAFT23, DockerTlsServerType.OPENSSL,
                        "1.1.1-pre2" },
                { NamedGroup.SECP384R1,
                        new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA_PSS, HashAlgorithm.SHA256),
                        CipherSuite.TLS_AES_128_GCM_SHA256, ProtocolVersion.TLS13_DRAFT23, DockerTlsServerType.OPENSSL,
                        "1.1.1-pre2" },
                { NamedGroup.SECP521R1,
                        new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA_PSS, HashAlgorithm.SHA256),
                        CipherSuite.TLS_AES_128_GCM_SHA256, ProtocolVersion.TLS13_DRAFT23, DockerTlsServerType.OPENSSL,
                        "1.1.1-pre2" } });
    }

    public Tls13HandshakeTests(NamedGroup namedGroup, SignatureAndHashAlgorithm signAlgorithm, CipherSuite suite,
            ProtocolVersion tls13Version, DockerTlsServerType serverType, String version) {
        this.namedGroup = namedGroup;
        this.signAlgorithm = signAlgorithm;
        this.suite = suite;
        this.tls13Version = tls13Version;
        this.serverType = serverType;
        this.version = version;
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

    @After
    public void tearDown() {
        if (server != null) {
            server.kill();
        }
    }

    @Test
    public void testTls13() {
        serverManager = DockerTlsServerManagerFactory.get(serverType, version);
        server = serverManager.getTlsServer();
        Config config = Config.createConfig();

        config.setWorkflowTraceType(WorkflowTraceType.FULL);
        config.setDefaultClientSupportedCiphersuites(suite);
        config.setDefaultSelectedCipherSuite(suite);
        config.setHighestProtocolVersion(tls13Version);
        config.setSupportedVersions(tls13Version);
        config.getDefaultClientConnection().setHostname(server.host);
        config.getDefaultClientConnection().setPort(server.port);
        config.setSupportedSignatureAndHashAlgorithms(signAlgorithm);
        config.setDefaultClientNamedGroups(namedGroup);
        config.setDefaultServerNamedGroups(namedGroup);
        config.setDefaultSelectedNamedGroup(namedGroup);
        config.setAddECPointFormatExtension(false);
        config.setAddEllipticCurveExtension(true);
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

    @Override
    public String toString() {
        return "Tls13HandshakeTests{" + "namedGroup=" + namedGroup + ", signAlgorithm=" + signAlgorithm + ", suite="
                + suite + ", tls13Version=" + tls13Version + ", serverType=" + serverType + ", version=" + version
                + '}';
    }
}
