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
import de.rub.nds.tlsattacker.core.layer.constant.LayerConfiguration;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import org.junit.jupiter.api.Tag;

@Tag(TestCategories.INTEGRATION_TEST)
public class ClientHttpHandshakeIT extends AbstractHandshakeIT {
    public ClientHttpHandshakeIT() {
        super(TlsImplementationType.OPENSSL, ConnectionRole.SERVER, "1.1.0f", "-www");
    }

    @Override
    protected boolean[] getCryptoExtensionsValues() {
        return new boolean[] {false};
    }

    @Override
    protected WorkflowTraceType[] getWorkflowTraceTypesToTest() {
        return new WorkflowTraceType[] {WorkflowTraceType.HTTPS, WorkflowTraceType.DYNAMIC_HTTPS};
    }

    @Override
    protected CipherSuite[] getCipherSuitesToTest() {
        return new CipherSuite[] {CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA};
    }

    @Override
    protected ProtocolVersion[] getProtocolVersionsToTest() {
        return new ProtocolVersion[] {ProtocolVersion.TLS12};
    }

    @Override
    protected NamedGroup[] getNamedGroupsToTest() {
        return new NamedGroup[] {NamedGroup.SECP256R1};
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
        config.setDefaultLayerConfiguration(LayerConfiguration.HTTPS);
    }
}
