/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
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
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.fail;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 *
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
public class TlsMitmTest {

    private static final Logger LOGGER = LogManager.getLogger(TlsMitmTest.class);
    private static final int SERVER_PORT = 44888;
    private static final int MITM_PORT = 44891;
    private BadRandom random = new BadRandom(new Random(0), null);

    public TlsMitmTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * TODO This test currently just executes the workflow. For validation,
     * write the trace to xml and compare it with a reference trace.
     */
    @Test
    @Category(IntegrationTests.class)
    public void checkSimpleMitmProxyWorkflow() {

        try {
            TimeHelper.setProvider(new FixedTimeProvider(0));
            KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024, random);
            KeyStore ks = KeyStoreGenerator.createKeyStore(k, random);
            BasicTlsServer serverThread = new BasicTlsServer(ks, KeyStoreGenerator.PASSWORD, "TLS", SERVER_PORT);

            CipherSuite cipherSuite = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA;
            // String mitmParams = server.getPort()..
            String mitmParams[] = new String[6];
            mitmParams[0] = "-connect";
            mitmParams[1] = "localhost:" + SERVER_PORT;
            mitmParams[2] = "-accept";
            mitmParams[3] = Integer.toString(MITM_PORT);
            mitmParams[4] = "-cipher";
            mitmParams[5] = cipherSuite.name();

            LOGGER.info("Starting test server");
            serverThread.start();
            while (!serverThread.isInitialized())
                ;

            // TimeUnit.SECONDS.sleep(4);

            LOGGER.info("Starting mitm");
            // FileHandler fileHandler = new FileHandler("myLogFile");
            // logger.addHandler(fileHandler);
            TlsMitm mitm = new TlsMitm(mitmParams);
            Thread mitmThread = new Thread(mitm);
            mitmThread.start();

            TimeUnit.SECONDS.sleep(1);

            LOGGER.info("Starting test client");
            BasicTlsClient clientThread = new BasicTlsClient("localhost", MITM_PORT, ProtocolVersion.TLS12, cipherSuite);
            clientThread.setRetryConnect(false);
            clientThread.start();
            mitmThread.join();

            LOGGER.info("Killing client");
            clientThread.interrupt();
            LOGGER.info("Done.");

            LOGGER.info("Killing mitm");
            mitmThread.interrupt();
            LOGGER.info("Done.");

            LOGGER.info("Killing server...");
            serverThread.shutdown();
            LOGGER.info("Done.");

        } catch (NoSuchAlgorithmException | CertificateException | IOException | InvalidKeyException
                | KeyStoreException | NoSuchProviderException | SignatureException | UnrecoverableKeyException
                | KeyManagementException | InterruptedException | OperatorCreationException ex) {
            ex.printStackTrace();
            fail();
        }
    }

}
