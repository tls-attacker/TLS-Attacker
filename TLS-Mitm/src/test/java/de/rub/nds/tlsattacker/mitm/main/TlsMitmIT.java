/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.mitm.main;

import de.rub.nds.modifiablevariable.util.BadRandom;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.util.BasicTlsClient;
import de.rub.nds.tlsattacker.core.util.BasicTlsServer;
import de.rub.nds.tlsattacker.core.util.KeyStoreGenerator;
import de.rub.nds.tlsattacker.util.FixedTimeProvider;
import de.rub.nds.tlsattacker.util.TimeHelper;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class TlsMitmIT {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final int MITM_PORT = 8877;
    private final BadRandom random = new BadRandom(new Random(0), null);

    private BasicTlsClient tlsClient;
    private BasicTlsServer tlsServer;

    @BeforeEach
    public void setUp()
            throws UnrecoverableKeyException,
                    CertificateException,
                    KeyStoreException,
                    IOException,
                    NoSuchAlgorithmException,
                    SignatureException,
                    InvalidKeyException,
                    NoSuchProviderException,
                    OperatorCreationException,
                    KeyManagementException {
        startBasicTlsServer();
    }

    @AfterEach
    public void tearDown() {
        tlsServer.shutdown();
        tlsClient.interrupt();
    }

    /**
     * TODO This test currently just executes the workflow. For validation, write the trace to xml
     * and compare it with a reference trace.
     */
    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testSimpleMitmProxyWorkflow()
            throws InterruptedException,
                    UnrecoverableKeyException,
                    CertificateException,
                    KeyStoreException,
                    IOException,
                    NoSuchAlgorithmException,
                    KeyManagementException {
        CipherSuite cipherSuite = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA;

        LOGGER.info("Starting test server");
        String[] mitmParams = new String[6];
        mitmParams[0] = "-connect";
        mitmParams[1] = "localhost:" + tlsServer.getPort();
        mitmParams[2] = "-accept";
        mitmParams[3] = Integer.toString(MITM_PORT);
        mitmParams[4] = "-cipher";
        mitmParams[5] = cipherSuite.name();

        LOGGER.info("Starting MitM");
        TlsMitm mitm = new TlsMitm(mitmParams);
        Thread mitmThread = new Thread(mitm);
        mitmThread.start();

        LOGGER.info("Starting test client");
        tlsClient = new BasicTlsClient("localhost", MITM_PORT, ProtocolVersion.TLS12, cipherSuite);
        tlsClient.setRetryConnect(true);
        tlsClient.start();
        mitmThread.join();
    }

    public void startBasicTlsServer()
            throws UnrecoverableKeyException,
                    CertificateException,
                    KeyStoreException,
                    IOException,
                    NoSuchAlgorithmException,
                    KeyManagementException,
                    SignatureException,
                    InvalidKeyException,
                    NoSuchProviderException,
                    OperatorCreationException {
        TimeHelper.setProvider(new FixedTimeProvider(0));
        KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024, random);
        KeyStore ks = KeyStoreGenerator.createKeyStore(k, random);
        tlsServer = new BasicTlsServer(ks, KeyStoreGenerator.PASSWORD, "TLS", 0);
        tlsServer.start();
        while (!tlsServer.isInitialized())
            ;
    }
}
