/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.modifiablevariable.util.BadRandom;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.util.FixedTimeProvider;
import de.rub.nds.tlsattacker.util.TimeHelper;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.*;

public class CertificateFetcherIT {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final int SERVER_PORT = 4999;

    private static BasicTlsServer tlsServer;
    private static PublicKey expectedPublicKey;
    private static Certificate expectedCertificate;

    @BeforeAll
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        TimeHelper.setProvider(new FixedTimeProvider(0));
        KeyPair k =
                KeyStoreGenerator.createRSAKeyPair(1024, new BadRandom(new Random(0), new byte[0]));
        KeyStore ks =
                KeyStoreGenerator.createKeyStore(k, new BadRandom(new Random(0), new byte[0]));

        expectedCertificate = ks.getCertificate(KeyStoreGenerator.ALIAS);
        expectedPublicKey = expectedCertificate.getPublicKey();

        tlsServer = new BasicTlsServer(ks, KeyStoreGenerator.PASSWORD, "TLS", SERVER_PORT);

        LOGGER.info("Starting test server");
        new Thread(tlsServer).start();
        while (!tlsServer.isInitialized())
            ;
    }

    @AfterAll
    public static void tearDownClass() {
        LOGGER.info("Killing server...");
        tlsServer.shutdown();
        LOGGER.info("Done.");
    }

    private Config config;

    @BeforeEach
    public void setUp() {
        config = Config.createConfig();
        ClientDelegate clientDelegate = new ClientDelegate();
        clientDelegate.setHost("localhost:" + SERVER_PORT);
        clientDelegate.applyDelegate(config);
    }

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testFetchServerPublicKey() {
        PublicKey actual;
        try {
            actual = CertificateFetcher.fetchServerPublicKey(config);
        } catch (CertificateParsingException ex) {
            LOGGER.warn("Could not parse certificate: ", ex);
            actual = null;
        }
        assertNotNull(actual);
        assertEquals(expectedPublicKey, actual);
    }

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testFetchServerCertificate() throws Exception {
        byte[] actualEncoded =
                CertificateFetcher.fetchServerCertificate(config)
                        .getCertificateList()[0]
                        .getEncoded();
        Certificate actual =
                CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(actualEncoded));
        assertNotNull(actual);
        assertEquals(expectedCertificate, actual);
    }
}
