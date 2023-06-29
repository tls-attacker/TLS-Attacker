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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import org.junit.jupiter.api.Tag;

@Tag(TestCategories.INTEGRATION_TEST)
public class ClientEcdsaHandshakeIT extends AbstractHandshakeIT {

    public ClientEcdsaHandshakeIT() {
        super(
                TlsImplementationType.MBEDTLS,
                ConnectionRole.SERVER,
                "2.6.0",
                "debug_level=5 crt_file=/cert/ec256cert.pem key_file=/cert/ec256key.pem");
    }

    @Override
    protected CipherSuite[] getCipherSuitesToTest() {
        return new CipherSuite[] {
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
        };
    }

    @Override
    protected ProtocolVersion[] getProtocolVersionsToTest() {
        return new ProtocolVersion[] {ProtocolVersion.TLS12};
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
