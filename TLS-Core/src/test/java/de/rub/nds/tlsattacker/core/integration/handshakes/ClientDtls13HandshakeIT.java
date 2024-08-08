/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.integration.handshakes;

import static de.rub.nds.tlsattacker.core.constants.CipherSuite.getTls13CipherSuites;

import de.rub.nds.tls.subject.ConnectionRole;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tls.subject.constants.TransportType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import org.junit.jupiter.api.Tag;

@Tag(TestCategories.INTEGRATION_TEST)
public class ClientDtls13HandshakeIT extends AbstractHandshakeIT {

    public ClientDtls13HandshakeIT() {
        super(
                TlsImplementationType.WOLFSSL,
                ConnectionRole.SERVER,
                "5.5.3-stable",
                "-dtls",
                TransportType.UDP);
    }

    @Override
    protected CipherSuite[] getCipherSuitesToTest() {
        return getTls13CipherSuites().toArray(CipherSuite[]::new);
    }

    @Override
    protected ProtocolVersion[] getProtocolVersionsToTest() {
        return new ProtocolVersion[] {ProtocolVersion.DTLS13};
    }

    @Override
    protected boolean[] getCryptoExtensionsValues() {
        return new boolean[] {false};
    }

    @Override
    protected WorkflowTraceType[] getWorkflowTraceTypesToTest() {
        return new WorkflowTraceType[] {WorkflowTraceType.HANDSHAKE};
    }
}
