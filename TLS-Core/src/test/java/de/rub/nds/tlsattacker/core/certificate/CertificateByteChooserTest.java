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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author robert
 */
public class CertificateByteChooserTest {

    private CertificateByteChooser chooser;

    public CertificateByteChooserTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
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
            System.out.println("-------------------------");
            System.out.println("Pk type:" + pair.getCertPublicKeyType());
            System.out.println("Cert signature type: " + pair.getCertSignatureType());
            System.out.println("PublickeyGroup: " + pair.getPublicKeyGroup());
            System.out.println("Signature group : " + pair.getSignatureGroup());
        }
    }

    @Test
    public void testChooseCertificateKeyPair() {
    }

}
