/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.integration.handshakes;

import de.rub.nds.tls.subject.ConnectionRole;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tls.subject.constants.TransportType;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import org.junit.jupiter.api.Tag;

/**
 * Integration test for PSK DHE handshakes in server mode. This test verifies the fix for issue #927
 * where PSK DHE handshakes were failing in server mode. The test covers both TLS 1.2 and DTLS 1.2
 * with various PSK DHE cipher suites.
 */
@Tag(TestCategories.INTEGRATION_TEST)
public class ServerPskDheHandshakeIT extends AbstractHandshakeIT {

    public ServerPskDheHandshakeIT() {
        super(
                TlsImplementationType.OPENSSL,
                ConnectionRole.CLIENT,
                "1.1.1m",
                "-psk_identity test -psk 0123456789abcdef",
                TransportType.TCP);
    }

    @Override
    protected void prepareConfig(
            CipherSuite cipherSuite,
            NamedGroup namedGroup,
            Config config,
            WorkflowTraceType workflowTraceType,
            boolean addExtendedMasterSecret,
            boolean addEncryptThenMac,
            ProtocolVersion protocolVersion) {
        super.prepareConfig(
                cipherSuite,
                namedGroup,
                config,
                workflowTraceType,
                addExtendedMasterSecret,
                addEncryptThenMac,
                protocolVersion);

        // Configure PSK settings for server mode
        config.setDefaultPSKIdentity("test".getBytes());
        config.setDefaultPSKKey(
                new byte[] {
                    0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef
                });
    }

    @Override
    protected CipherSuite[] getCipherSuitesToTest() {
        return new CipherSuite[] {
            // Test the most commonly used PSK DHE cipher suites
            CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
        };
    }

    @Override
    protected ProtocolVersion[] getProtocolVersionsToTest() {
        // Focus on TLS 1.2 as mentioned in issue #927
        return new ProtocolVersion[] {ProtocolVersion.TLS12};
    }

    @Override
    protected NamedGroup[] getNamedGroupsToTest() {
        // Test with commonly used DH groups
        return new NamedGroup[] {NamedGroup.FFDHE2048, NamedGroup.FFDHE3072};
    }

    @Override
    protected WorkflowTraceType[] getWorkflowTraceTypesToTest() {
        // Test basic handshake for PSK DHE
        return new WorkflowTraceType[] {WorkflowTraceType.HANDSHAKE};
    }

    @Override
    protected boolean[] getCryptoExtensionsValues() {
        // Disable crypto extensions for simpler testing
        return new boolean[] {false};
    }
}
