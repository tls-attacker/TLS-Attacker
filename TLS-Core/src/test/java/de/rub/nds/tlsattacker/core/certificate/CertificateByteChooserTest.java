/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.certificate;

import java.security.Security;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

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

    private CertificateByteChooser chooser;

    public CertificateByteChooserTest() {
    }

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        chooser = CertificateByteChooser.getInstance();
    }

    @After
    public void tearDown() {
    }

    @Test
    public void testGetCertificateKeyPairList() {
        List<CertificateKeyPair> certificateKeyPairList = chooser.getCertificateKeyPairList();
        for (CertificateKeyPair pair : certificateKeyPairList) {
            LOGGER.debug("-------------------------");
            LOGGER.debug("Pk type:" + pair.getCertPublicKeyType());
            LOGGER.debug("Cert signature type: " + pair.getCertSignatureType());
            LOGGER.debug("PublickeyGroup: " + pair.getPublicKeyGroup());
        }
    }

    @Test
    public void testChooseCertificateKeyPair() {
    }

}
