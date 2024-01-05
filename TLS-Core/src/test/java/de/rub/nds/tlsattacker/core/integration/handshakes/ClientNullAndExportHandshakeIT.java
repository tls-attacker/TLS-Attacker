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
public class ClientNullAndExportHandshakeIT extends AbstractHandshakeIT {

    public ClientNullAndExportHandshakeIT() {
        super(
                TlsImplementationType.OPENSSL,
                ConnectionRole.SERVER,
                "1.0.1g",
                "-cipher NULL:aNULL:ALL");
    }

    @Override
    protected WorkflowTraceType[] getWorkflowTraceTypesToTest() {
        return new WorkflowTraceType[] {WorkflowTraceType.HANDSHAKE};
    }

    @Override
    protected boolean[] getCryptoExtensionsValues() {
        return new boolean[] {false};
    }

    @Override
    protected CipherSuite[] getCipherSuitesToTest() {
        return new CipherSuite[] {
            CipherSuite.TLS_RSA_WITH_NULL_MD5,
            CipherSuite.TLS_RSA_WITH_NULL_SHA,
            CipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
            CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5,
            CipherSuite.TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA,
            CipherSuite.TLS_DH_anon_WITH_DES_CBC_SHA,
            CipherSuite.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_NULL_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA,
            CipherSuite.TLS_ECDH_anon_WITH_NULL_SHA,
            // We also test SSLv3 with one strong cipher suite.
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        };
    }

    @Override
    protected ProtocolVersion[] getProtocolVersionsToTest() {
        return new ProtocolVersion[] {
            ProtocolVersion.TLS10,
            ProtocolVersion.TLS11,
            ProtocolVersion.TLS12,
            ProtocolVersion.SSL3
        };
    }
}
