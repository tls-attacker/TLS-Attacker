/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.modifiablevariable.util.BadRandom;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.util.FixedTimeProvider;
import de.rub.nds.tlsattacker.util.TimeHelper;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class BasicTlsClientServerIT {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final int SERVER_PORT = 0;
    private final BadRandom random = new BadRandom(new Random(0), null);

    /**
     * Run a TLS handshake between BasicTlsClient and BasicTlsServer.
     *
     * @throws org.bouncycastle.operator.OperatorCreationException
     */
    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testSimpleProxy()
            throws OperatorCreationException,
                    NoSuchAlgorithmException,
                    UnrecoverableKeyException,
                    CertificateException,
                    KeyStoreException,
                    IOException,
                    KeyManagementException,
                    SignatureException,
                    InvalidKeyException,
                    NoSuchProviderException,
                    InterruptedException {
        TimeHelper.setProvider(new FixedTimeProvider(0));
        KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024, random);
        KeyStore ks = KeyStoreGenerator.createKeyStore(k, random);
        BasicTlsServer tlsServer =
                new BasicTlsServer(ks, KeyStoreGenerator.PASSWORD, "TLS", SERVER_PORT);

        LOGGER.info("Starting test server");
        new Thread(tlsServer).start();
        while (!tlsServer.isInitialized())
            ;

        LOGGER.info("Starting test client");
        BasicTlsClient client =
                new BasicTlsClient(
                        "localhost",
                        tlsServer.getPort(),
                        ProtocolVersion.TLS12,
                        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        client.setRetryConnect(false);
        Thread clientThread = new Thread(client);
        clientThread.start();

        TimeUnit.SECONDS.sleep(1);

        LOGGER.info("Killing client");
        clientThread.interrupt();
        LOGGER.info("Done.");

        LOGGER.info("Killing server...");
        tlsServer.shutdown();
        LOGGER.info("Done.");
    }
}
