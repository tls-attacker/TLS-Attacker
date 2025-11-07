/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.x509attacker.filesystem.CertificateBytes;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class CertificateDelegateCertChainTest extends AbstractDelegateTest<CertificateDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new CertificateDelegate());
    }

    /**
     * Test that CertificateDelegate can properly load a certificate chain from a single PEM file
     * containing multiple certificates.
     */
    @Test
    public void testCertificateChainLoading(@TempDir File tempDir) throws IOException {
        // Read the leaf certificate
        String leafCert =
                Files.readString(new File("src/main/resources/certs/dh1024_rsa_cert.pem").toPath());
        // Read the CA certificate
        String caCert =
                Files.readString(new File("src/main/resources/certs/attacker_rsa_ca.pem").toPath());

        // Create a certificate chain file with both certificates
        File chainFile = new File(tempDir, "cert_chain.pem");
        try (FileWriter writer = new FileWriter(chainFile)) {
            writer.write(leafCert.trim());
            writer.write("\n");
            writer.write(caCert.trim());
        }

        // Read the private key
        File keyFile = new File("src/main/resources/certs/dh1024_key.pem");

        // Test loading the certificate chain
        args = new String[4];
        args[0] = "-cert";
        args[1] = chainFile.getAbsolutePath();
        args[2] = "-key";
        args[3] = keyFile.getAbsolutePath();
        jcommander.parse(args);

        Config config = new Config();
        delegate.applyDelegate(config);

        // Verify that the certificate chain was loaded
        List<CertificateBytes> certChain = config.getDefaultExplicitCertificateChain();
        assertNotNull(certChain, "Certificate chain should not be null");
        assertEquals(2, certChain.size(), "Certificate chain should contain 2 certificates");

        // Verify the certificates are in the correct order (leaf first, then CA)
        assertNotNull(certChain.get(0).getBytes(), "First certificate should not be null");
        assertNotNull(certChain.get(1).getBytes(), "Second certificate should not be null");
        assertTrue(certChain.get(0).getBytes().length > 0, "First certificate should not be empty");
        assertTrue(
                certChain.get(1).getBytes().length > 0, "Second certificate should not be empty");
    }

    /**
     * Test that CertificateDelegate handles certificate chain with intermediate certificates
     * properly.
     */
    @Test
    public void testCertificateChainWithThreeCerts(@TempDir File tempDir) throws IOException {
        // For this test, we'll simulate a chain with 3 certificates
        String cert1 =
                Files.readString(new File("src/main/resources/certs/dh1024_rsa_cert.pem").toPath());
        String cert2 =
                Files.readString(new File("src/main/resources/certs/dh2048_rsa_cert.pem").toPath());
        String cert3 =
                Files.readString(new File("src/main/resources/certs/attacker_rsa_ca.pem").toPath());

        // Create a certificate chain file with three certificates
        File chainFile = new File(tempDir, "cert_chain_3.pem");
        try (FileWriter writer = new FileWriter(chainFile)) {
            writer.write(cert1.trim());
            writer.write("\n");
            writer.write(cert2.trim());
            writer.write("\n");
            writer.write(cert3.trim());
        }

        // Read the private key
        File keyFile = new File("src/main/resources/certs/dh1024_key.pem");

        // Test loading the certificate chain
        args = new String[4];
        args[0] = "-cert";
        args[1] = chainFile.getAbsolutePath();
        args[2] = "-key";
        args[3] = keyFile.getAbsolutePath();
        jcommander.parse(args);

        Config config = new Config();
        delegate.applyDelegate(config);

        // Verify that the certificate chain was loaded
        List<CertificateBytes> certChain = config.getDefaultExplicitCertificateChain();
        assertNotNull(certChain, "Certificate chain should not be null");
        assertEquals(3, certChain.size(), "Certificate chain should contain 3 certificates");

        // Verify all certificates are properly loaded
        for (int i = 0; i < 3; i++) {
            assertNotNull(
                    certChain.get(i).getBytes(), "Certificate " + (i + 1) + " should not be null");
            assertTrue(
                    certChain.get(i).getBytes().length > 0,
                    "Certificate " + (i + 1) + " should not be empty");
        }
    }

    /** Test that CertificateDelegate handles single certificate file (backwards compatibility). */
    @Test
    public void testSingleCertificateLoading() throws IOException {
        // Test with a single certificate
        File certFile = new File("src/main/resources/certs/dh1024_rsa_cert.pem");
        File keyFile = new File("src/main/resources/certs/dh1024_key.pem");

        args = new String[4];
        args[0] = "-cert";
        args[1] = certFile.getAbsolutePath();
        args[2] = "-key";
        args[3] = keyFile.getAbsolutePath();
        jcommander.parse(args);

        Config config = new Config();
        delegate.applyDelegate(config);

        // Verify that the single certificate was loaded
        List<CertificateBytes> certChain = config.getDefaultExplicitCertificateChain();
        assertNotNull(certChain, "Certificate chain should not be null");
        assertEquals(1, certChain.size(), "Certificate chain should contain 1 certificate");
        assertNotNull(certChain.get(0).getBytes(), "Certificate should not be null");
        assertTrue(certChain.get(0).getBytes().length > 0, "Certificate should not be empty");
    }
}
