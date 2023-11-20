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
import de.rub.nds.protocol.crypto.key.PublicKeyContainer;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.util.FixedTimeProvider;
import de.rub.nds.tlsattacker.util.TimeHelper;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.x509attacker.filesystem.CertificateIo;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateParsingException;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class CertificateFetcherTest {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final int SERVER_PORT = 4999;

    private static BasicTlsServer tlsServer;
    private static PublicKeyContainer expectedPublicKey;
    private static X509CertificateChain expectedCertificate;

    @BeforeAll
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        TimeHelper.setProvider(new FixedTimeProvider(0));
        KeyPair keyPair =
                KeyStoreGenerator.createRSAKeyPair(1024, new BadRandom(new Random(0), new byte[0]));
        KeyStore keyStore =
                KeyStoreGenerator.createKeyStore(
                        keyPair, new BadRandom(new Random(0), new byte[0]));

        expectedCertificate =
                CertificateIo.convert(keyStore.getCertificate(KeyStoreGenerator.ALIAS));
        expectedPublicKey = expectedCertificate.getLeaf().getPublicKeyContainer();

        tlsServer = new BasicTlsServer(keyStore, KeyStoreGenerator.PASSWORD, "TLS", SERVER_PORT);

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
        PublicKeyContainer actual;
        try {
            actual = CertificateFetcher.fetchServerPublicKey(config);
        } catch (CertificateParsingException ex) {
            LOGGER.warn("Could not parse certificate: ", ex);
            actual = null;
        }
        assertNotNull(actual);
        // assertArrayEquals(
        //        expectedPublicKey, actual.getSerializer().serialize());
        // TODO replace with correct value comparision
    }

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testFetchServerCertificate() throws Exception {

        X509CertificateChain fetchedChain = CertificateFetcher.fetchServerCertificateChain(config);
        assertNotNull(fetchedChain);
        assertEquals(
                expectedCertificate.getCertificateList().size(),
                fetchedChain.getCertificateList().size());
        Assertions.assertArrayEquals(
                expectedCertificate.getLeaf().getSerializer(null).serialize(),
                fetchedChain.getLeaf().getSerializer(null).serialize());
    }
}
