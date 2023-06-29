/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import de.rub.nds.tlsattacker.core.constants.CertificateKeyType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.security.Security;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CertificateByteChooserTest {

    private static final Logger LOGGER = LogManager.getLogger();

    private CertificateByteChooser byteChooser;
    private Chooser defaultChooser;

    @BeforeAll
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeEach
    public void setUp() {
        byteChooser = CertificateByteChooser.getInstance();

        TlsContext tlsContext = new TlsContext();
        defaultChooser = tlsContext.getChooser();
    }

    @Test
    public void testGetCertificateKeyPairList() {
        List<CertificateKeyPair> certificateKeyPairList = byteChooser.getCertificateKeyPairList();
        for (CertificateKeyPair pair : certificateKeyPairList) {
            LOGGER.debug("-------------------------");
            LOGGER.debug("Pk type:" + pair.getCertPublicKeyType());
            LOGGER.debug("Cert signature type: " + pair.getCertSignatureType());
            LOGGER.debug("Cert signatureAndHashAlgo: " + pair.getSignatureAndHashAlgorithm());
            LOGGER.debug("PublicKeyGroup: " + pair.getPublicKeyGroup());
            assertNotEquals(
                    SignatureAndHashAlgorithm.ANONYMOUS_NONE, pair.getSignatureAndHashAlgorithm());
        }
    }

    @Test
    public void testChooseCertificateKeyPair() {
        defaultChooser
                .getContext()
                .getTlsContext()
                .setSelectedCipherSuite(CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA);
        defaultChooser
                .getContext()
                .getTlsContext()
                .setClientSupportedCertificateSignAlgorithms(
                        SignatureAndHashAlgorithm.RSA_SHA224,
                        SignatureAndHashAlgorithm.RSA_SHA256,
                        SignatureAndHashAlgorithm.ECDSA_SHA256);
        defaultChooser
                .getContext()
                .getTlsContext()
                .setClientNamedGroupsList(NamedGroup.SECP256R1, NamedGroup.SECT163R1);
        CertificateKeyPair selectedKeyPair = byteChooser.chooseCertificateKeyPair(defaultChooser);
        assertEquals(CertificateKeyType.ECDH, selectedKeyPair.getCertPublicKeyType());
        assertEquals(NamedGroup.SECP256R1, selectedKeyPair.getPublicKeyGroup());
        assertEquals(
                SignatureAndHashAlgorithm.RSA_SHA256,
                selectedKeyPair.getSignatureAndHashAlgorithm());
    }
}
