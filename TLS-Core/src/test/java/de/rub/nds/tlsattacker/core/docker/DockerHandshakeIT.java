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
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import de.rub.nds.tlsattacker.util.tests.DockerTests;
import java.security.Security;
import java.util.Arrays;
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
        return Arrays.asList(new Object[][] {
                { true, true, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS10,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS11,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { true, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { true, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, true, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION },
                { false, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.HANDSHAKE },
                { false, false, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, ProtocolVersion.TLS12,
                        WorkflowTraceType.FULL_RESUMPTION }, });
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
        config.getDefaultClientConnection().setHostname(server.host);
        config.getDefaultClientConnection().setPort(server.port);
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
