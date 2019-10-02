/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.modifiablevariable.util.BadRandom;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.util.FixedTimeProvider;
import de.rub.nds.tlsattacker.util.TimeHelper;
import de.rub.nds.tlsattacker.util.tests.IntegrationTests;
import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

public class CertificateFetcherTest {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final int SERVER_PORT = 4999;

    private static BasicTlsServer tlsServer;
    private static PublicKey expectedPublicKey;
    private static Certificate expectedCertificate;

    @BeforeClass
    public static void setUpClass() throws Exception {
        TimeHelper.setProvider(new FixedTimeProvider(0));
        KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024, new BadRandom(new Random(0), new byte[0]));
        KeyStore ks = null;
        ks = KeyStoreGenerator.createKeyStore(k, new BadRandom(new Random(0), new byte[0]));

        expectedCertificate = ks.getCertificate(KeyStoreGenerator.ALIAS);
        expectedPublicKey = expectedCertificate.getPublicKey();

        tlsServer = new BasicTlsServer(ks, KeyStoreGenerator.PASSWORD, "TLS", SERVER_PORT);

        LOGGER.info("Starting test server");
        new Thread(tlsServer).start();
        while (!tlsServer.isInitialized())
            ;
    }

    @AfterClass
    public static void tearDownClass() {
        LOGGER.info("Killing server...");
        tlsServer.shutdown();
        LOGGER.info("Done.");
    }

    private Config config;

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        config = Config.createConfig();
        ClientDelegate clientDelegate = new ClientDelegate();
        clientDelegate.setHost("localhost:" + SERVER_PORT);
        clientDelegate.applyDelegate(config);
    }

    @After
    public void tearDown() {
    }

    @Test
    @Category(IntegrationTests.class)
    public void testFetchServerPublicKey() {
        PublicKey actual = CertificateFetcher.fetchServerPublicKey(config);
        assertNotNull(actual);
        assertEquals(expectedPublicKey, actual);
    }

    @Test
    @Category(IntegrationTests.class)
    public void testFetchServerCertificate() throws Exception {
        byte[] actualEncoded = CertificateFetcher.fetchServerCertificate(config).getCertificateList()[0].getEncoded();
        Certificate actual = CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(actualEncoded));
        assertNotNull(actual);
        assertEquals(expectedCertificate, actual);
    }

}
