/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.certificate;

import java.security.Security;
import java.util.List;

import de.rub.nds.tlsattacker.core.constants.CertificateKeyType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

/**
 *
 *
 */
public class CertificateByteChooserTest {

    private final static Logger LOGGER = LogManager.getLogger();

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    private CertificateByteChooser byteChooser;
    private Chooser defaultChooser;

    public CertificateByteChooserTest() {
    }

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        byteChooser = CertificateByteChooser.getInstance();

        TlsContext context = new TlsContext();
        defaultChooser = context.getChooser();
    }

    @After
    public void tearDown() {
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
            assertNotEquals(pair.getSignatureAndHashAlgorithm(), SignatureAndHashAlgorithm.ANONYMOUS_NONE);
        }
    }

    @Test
    public void testChooseCertificateKeyPair() {
        defaultChooser.getContext().setSelectedCipherSuite(CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA);
        defaultChooser.getContext().setClientSupportedCertificateSignAlgorithms(SignatureAndHashAlgorithm.RSA_SHA224,
            SignatureAndHashAlgorithm.RSA_SHA256, SignatureAndHashAlgorithm.ECDSA_SHA256);
        defaultChooser.getContext().setClientNamedGroupsList(NamedGroup.SECP256R1, NamedGroup.SECT163R1);
        CertificateKeyPair selectedKeyPair = byteChooser.chooseCertificateKeyPair(defaultChooser);
        assertEquals(CertificateKeyType.ECDH, selectedKeyPair.getCertPublicKeyType());
        assertEquals(NamedGroup.SECP256R1, selectedKeyPair.getPublicKeyGroup());
        assertEquals(SignatureAndHashAlgorithm.RSA_SHA256, selectedKeyPair.getSignatureAndHashAlgorithm());
    }

}
