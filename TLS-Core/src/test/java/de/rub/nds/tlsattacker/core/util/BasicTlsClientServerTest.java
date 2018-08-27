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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.util.FixedTimeProvider;
import de.rub.nds.tlsattacker.util.TimeHelper;
import de.rub.nds.tlsattacker.util.tests.IntegrationTests;
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
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.operator.OperatorCreationException;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.experimental.categories.Category;

public class BasicTlsClientServerTest {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final int SERVER_PORT = 0;
    private final BadRandom random = new BadRandom(new Random(0), null);

    public BasicTlsClientServerTest() {
    }

    /**
     * Run a TLS handshake between BasicTlsClient and BasicTlsServer.
     *
     * @throws org.bouncycastle.operator.OperatorCreationException
     */
    @Test
    @Category(IntegrationTests.class)
    public void testSimpleProxy() throws OperatorCreationException {

        try {
            TimeHelper.setProvider(new FixedTimeProvider(0));
            KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024, random);
            KeyStore ks = KeyStoreGenerator.createKeyStore(k, random);
            BasicTlsServer tlsServer = new BasicTlsServer(ks, KeyStoreGenerator.PASSWORD, "TLS", SERVER_PORT);

            LOGGER.info("Starting test server");
            new Thread(tlsServer).start();
            while (!tlsServer.isInitialized())
                ;

            LOGGER.info("Starting test client");
            BasicTlsClient client = new BasicTlsClient("localhost", tlsServer.getPort(), ProtocolVersion.TLS12,
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
        } catch (NoSuchAlgorithmException | CertificateException | IOException | InvalidKeyException
                | KeyStoreException | NoSuchProviderException | SignatureException | UnrecoverableKeyException
                | KeyManagementException | InterruptedException ex) {
            fail();
        }
    }

    private Random Random(int i) {
        throw new UnsupportedOperationException("Not supported yet."); // To
        // change
        // body
        // of
        // generated
        // methods,
        // choose
        // Tools
        // |
        // Templates.
    }
}
