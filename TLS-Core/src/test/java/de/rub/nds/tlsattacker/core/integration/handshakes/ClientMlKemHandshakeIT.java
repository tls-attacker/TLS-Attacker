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
public class ClientMlKemHandshakeIT extends AbstractHandshakeIT {

    public ClientMlKemHandshakeIT() {
        super(
                TlsImplementationType.OPENSSL,
                ConnectionRole.SERVER,
                "3.5.0",
                "-tls1_3 -groups MLKEM512:MLKEM768:MLKEM1024:X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024");
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
        return new NamedGroup[] {
            NamedGroup.MLKEM512,
            NamedGroup.MLKEM768,
            NamedGroup.MLKEM1024,
            NamedGroup.X25519_MLKEM768,
            NamedGroup.SECP256R1_MLKEM768,
            NamedGroup.SECP384R1_MLKEM1024
        };
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
        config.setDefaultClientNamedGroups(namedGroup);
        config.setDefaultClientKeyShareNamedGroups(namedGroup);
    }
}
