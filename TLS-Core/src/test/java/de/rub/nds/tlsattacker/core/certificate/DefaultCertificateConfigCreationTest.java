/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import de.rub.nds.x509attacker.x509.X509CertificateChainBuilder;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import org.junit.jupiter.api.Test;

public class DefaultCertificateConfigCreationTest {

    @Test
    public void testDefaultCertificateCreation() throws Exception {
        Config config = new Config();
        X509CertificateChainBuilder builder = new X509CertificateChainBuilder();
        X509CertificateChain buildChain = builder.buildChain(config.getCertificateChainConfig());
        for (X509Certificate certificate : buildChain.getCertificateList()) {
            System.out.println(
                    ArrayConverter.bytesToHexString(certificate.getSerializer(null).serialize()));
        }
    }
}
