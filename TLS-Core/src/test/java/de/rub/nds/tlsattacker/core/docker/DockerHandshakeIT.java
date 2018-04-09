/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.docker;

import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tls.subject.TlsServer;
import de.rub.nds.tls.subject.docker.DockerTlsServerManagerFactory;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import de.rub.nds.tlsattacker.util.tests.DockerTests;
import java.security.Security;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@Category(DockerTests.class)
@RunWith(Parameterized.class)
public class DockerHandshakeIT {

    private static TlsServer server;

    @Parameters
    public static Collection<Object[]> data() {
        boolean[] addEncryptThenMacValues = { true, false };
        boolean[] addExtendedMasterSecretValues = { true, false };
        CipherSuite[] cipherSuites = { CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA };
        ProtocolVersion[] protocolVersions = { ProtocolVersion.TLS10, ProtocolVersion.TLS11, ProtocolVersion.TLS12 };
        WorkflowTraceType[] workflowTraceTypes = { WorkflowTraceType.HANDSHAKE, WorkflowTraceType.FULL_RESUMPTION };

        List<Object[]> res = new LinkedList<Object[]>();
        for (boolean addEncryptThenMac : addEncryptThenMacValues) {
            for (boolean addExtendedMasterSecret : addExtendedMasterSecretValues) {
                for (CipherSuite cipherSuite : cipherSuites) {
                    for (ProtocolVersion protocolVersion : protocolVersions) {
                        for (WorkflowTraceType workflowTraceType : workflowTraceTypes) {
                            res.add(new Object[] { addEncryptThenMac, addExtendedMasterSecret, cipherSuite,
                                    protocolVersion, workflowTraceType });
                        }
                    }
                }
            }
        }
        return res;
    }

    private Boolean addEncryptThenMac;

    private Boolean addExtendedMasterSecret;

    private CipherSuite suite;

    private ProtocolVersion version;

    private WorkflowTraceType traceType;

    public DockerHandshakeIT(Boolean addEncryptThenMac, Boolean addExtendedMasterSecret, CipherSuite suite,
            ProtocolVersion version, WorkflowTraceType traceType) {
        this.addEncryptThenMac = addEncryptThenMac;
        this.addExtendedMasterSecret = addExtendedMasterSecret;
        this.suite = suite;
        this.version = version;
        this.traceType = traceType;
    }

    @BeforeClass
    public static void setUp() {
        System.out.println("Trying to initialize DockerTests");
        UnlimitedStrengthEnabler.enable();
        Security.addProvider(new BouncyCastleProvider());
        DockerTlsServerManagerFactory factory = new DockerTlsServerManagerFactory();
        server = factory.get(TlsImplementationType.OPENSSL, "1.1.0f");

        System.out.println("Started the Docker server at:" + server.getHost() + ":" + server.getPort());
    }

    @AfterClass
    public static void tearDown() {
        // System.out.println(server.getServerLogs());
        server.kill();
    }

    @Test
    public void testClientHandshakes() {
        Config config = Config.createConfig();
        if (AlgorithmResolver.getKeyExchangeAlgorithm(suite).isEC()) {
            config.setAddECPointFormatExtension(Boolean.TRUE);
            config.setAddEllipticCurveExtension(Boolean.TRUE);
        } else {
            config.setAddECPointFormatExtension(Boolean.FALSE);
            config.setAddEllipticCurveExtension(Boolean.FALSE);
        }
        config.setWorkflowTraceType(traceType);
        config.setAddExtendedMasterSecretExtension(addExtendedMasterSecret);
        config.setAddEncryptThenMacExtension(addEncryptThenMac);
        config.setDefaultClientSupportedCiphersuites(suite);
        config.setDefaultSelectedCipherSuite(suite);
        config.setHighestProtocolVersion(version);
        config.setSupportedVersions(version);
        config.getDefaultClientConnection().setHostname(server.getHost());
        config.getDefaultClientConnection().setPort(server.getPort());
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
        return "DockerHandshakeIT{" + "addEncryptThenMac=" + addEncryptThenMac + ", addExtendedMasterSecret="
                + addExtendedMasterSecret + ", suite=" + suite + ", version=" + version + ", traceType=" + traceType
                + '}';
    }

}
