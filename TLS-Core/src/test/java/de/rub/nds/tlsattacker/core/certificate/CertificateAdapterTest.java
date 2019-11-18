/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.certificate;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import static org.junit.Assert.assertEquals;
import org.junit.BeforeClass;
import org.junit.Test;

public class CertificateAdapterTest {

    private static Certificate certificate;
    private final CertificateAdapter certificateAdapter = new CertificateAdapter();

    /**
     * Creates a TLS certificate to test on
     *
     * @throws NoSuchAlgorithmException
     * @throws OperatorCreationException
     * @throws java.io.IOException
     */
    @BeforeClass
    public static void setUpClass() throws NoSuchAlgorithmException, OperatorCreationException, IOException, Exception {

        // Generate 2048 Bit RSA Keypair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privK = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Set validity to one year
        Date startDate = new Date(System.currentTimeMillis());
        Date endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000);

        // Initialize certificate generating objects
        X509v1CertificateBuilder certificateBuilder = new JcaX509v1CertificateBuilder(new X500Principal("CN=Test"),
                BigInteger.ONE, startDate, endDate, new X500Principal("CN=Test"), publicKey);
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider()).build(privK);

        // Create certificate
        X509CertificateHolder certHolder = certificateBuilder.build(contentSigner);
        certificate = new Certificate(new org.bouncycastle.asn1.x509.Certificate[] { certHolder.toASN1Structure() });
    }

    /**
     * Tests if marshal() creates the correct HexString corresponding to a given
     * certificate.
     *
     * @throws IOException
     * @throws Exception
     */
    @Test
    public void testCorrectMarshal() throws IOException, Exception {
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        certificate.encode(outStream);
        String correctCertificateString = ArrayConverter.bytesToHexString(outStream.toByteArray());
        String marshalledCertificateString = certificateAdapter.marshal(certificate);
        assertEquals(marshalledCertificateString, correctCertificateString);
    }

    /**
     * Tests if unmarshal() correctly throws an exception on an invalid input
     * string.
     *
     * @throws Exception
     */
    @Test(expected = Exception.class)
    public void testUnmarshalException() throws Exception {
        certificateAdapter.unmarshal("Not a certificate String.");
    }

    /**
     * Tests if marshal() correctly throws an exception on an invalid input
     * certificate.
     *
     * @throws Exception
     */
    @Test(expected = Exception.class)
    public void testMarshalException() throws Exception {
        certificateAdapter.marshal(null);
    }

    /**
     * Tests if unmarshal() is the reverse function of marshal(), i.e. for a
     * certificate c checks if marshal(c) = marshal(unmarshal(marshal(c)))
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testReversibility() throws Exception {
        String marshalledCertificate_1 = certificateAdapter.marshal(certificate);
        Certificate unmarshalledCertificate = certificateAdapter.unmarshal(marshalledCertificate_1);
        String marshalledCertificate_2 = certificateAdapter.marshal(unmarshalledCertificate);
        assertEquals(marshalledCertificate_1, marshalledCertificate_2);
    }

}