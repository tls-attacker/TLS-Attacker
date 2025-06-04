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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import org.junit.jupiter.api.Tag;

@Tag(TestCategories.INTEGRATION_TEST)
public class DebugHandshakeIT extends AbstractHandshakeIT {

    public DebugHandshakeIT() {
        // run OpenSSL with dummy HTTP server to get a reply for app data
        super(
                TlsImplementationType.OPENSSL,
                ConnectionRole.SERVER,
                "3.4.0",
                "-tls1_3 -curves brainpoolP256r1tls13");
    }

    @Override
    protected boolean[] getCryptoExtensionsValues() {
        return new boolean[] {false};
    }

    @Override
    protected WorkflowTraceType[] getWorkflowTraceTypesToTest() {
        return new WorkflowTraceType[] {
            WorkflowTraceType.HANDSHAKE,
        };
    }

    @Override
    protected CipherSuite[] getCipherSuitesToTest() {
        return new CipherSuite[] {CipherSuite.TLS_AES_128_GCM_SHA256};
    }

    @Override
    protected ProtocolVersion[] getProtocolVersionsToTest() {
        return new ProtocolVersion[] {ProtocolVersion.TLS13};
    }

    @Override
    protected NamedGroup[] getNamedGroupsToTest() {
        return new NamedGroup[] {NamedGroup.BRAINPOOLP256R1TLS13};
    }

    @Override
    protected void prepareConfig(
            CipherSuite cipherSuite,
            NamedGroup namedGroup,
            Config config,
            WorkflowTraceType workflowTraceType,
            boolean useCryptoExtensions,
            boolean useEarlyData,
            ProtocolVersion protocolVersion) {
        super.prepareConfig(
                cipherSuite,
                namedGroup,
                config,
                workflowTraceType,
                useCryptoExtensions,
                useEarlyData,
                protocolVersion);
        config.setAddDebugExtension(true);
        config.setDefaultDebugContent("TLS-Attacker Debug Content");
    }
}
