/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsattacker.mitm.main;

import java.security.Security;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.fail;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ErrorCollector;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.PublicKeyAlgorithm;
import de.rub.nds.tlsattacker.core.util.JKSLoader;
import de.rub.nds.tlsattacker.core.util.BasicTlsClient;
import de.rub.nds.tlsattacker.core.util.BasicTlsServer;
import de.rub.nds.tlsattacker.core.util.KeyStoreGenerator;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.util.FixedTimeProvider;
import de.rub.nds.tlsattacker.util.TimeHelper;
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
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.Level;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @author Lucas Hartmann <firstname.lastname@rub.de>
 */
public class TlsMitmTest {

    private static final Logger LOGGER = LogManager.getLogger(TlsMitmTest.class);

    private static int MITM_PORT = 4433;
    private static int SERVER_PORT = 4433;
    private BasicTlsServer tlsServer;

    @Rule
    public ErrorCollector collector = new ErrorCollector();

    public TlsMitmTest() {
        Security.addProvider(new BouncyCastleProvider());
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
     * Test of run method, of class TlsMitm.
     */
    // @Test
    // public void testRun() {
    // System.out.println("run");
    // TlsConfig config = null;
    // TlsMitm instance = new TlsMitm();
    // instance.run(config);
    // // TODO review the generated test code and remove the default call to
    // // fail.
    // //fail("The test case is a prototype.");
    // }

    @Test
    // @Category(IntegrationTests.class)
    public void testSimpleProxy() throws OperatorCreationException {

        try {
            TimeHelper.setProvider(new FixedTimeProvider(0));
            KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024);
            KeyStore ks = null;
            ks = KeyStoreGenerator.createKeyStore(k);
            tlsServer = new BasicTlsServer(ks, KeyStoreGenerator.PASSWORD, "TLS", SERVER_PORT);

            LOGGER.info("Starting test server");
            new Thread(tlsServer).start();
            while (!tlsServer.isInitialized());

            LOGGER.info("Starting test client");
            BasicTlsClient client = new BasicTlsClient();
            Thread t = new Thread(client);
            t.start();

            TimeUnit.SECONDS.sleep(1);

            LOGGER.info("Killing client");
            t.interrupt();
            LOGGER.info("Done.");

            LOGGER.info("Killing server...");
            tlsServer.shutdown();
            LOGGER.info("Done.");
        } catch (NoSuchAlgorithmException | CertificateException | IOException | InvalidKeyException
                | KeyStoreException | NoSuchProviderException | SignatureException | UnrecoverableKeyException
                | KeyManagementException | InterruptedException ex) {
            ex.printStackTrace();
            fail();
        }
    }

    // /**
    // * Test of executeWorkflow method, of class WorkflowExecutor.
    // *
    // * @param suite
    // * @param version
    // * @param port
    // */
    // public void testExecuteWorkflows(int port, CipherSuite suite,
    // ProtocolVersion version) {
    // TlsConfig config = TlsConfig.createConfig();
    // config.setConnectionEnd(ConnectionEnd.SERVER);
    // config.setHost("server");
    // config.setServerPort(port);
    // config.setTlsTimeout(2000);
    // config.setTimeout(2000);
    // config.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
    // config.setHighestProtocolVersion(version);
    // config.setOurCertificate(JKSLoader.loadTLSCertificate(config.getKeyStore(),
    // config.getAlias()));
    // List<CipherSuite> supportedSuites = new LinkedList<>();
    // supportedSuites.add(suite);
    // config.setSupportedCiphersuites(supportedSuites);
    // config.setEnforceSettings(true);
    // TlsContext context = new TlsContext(config);
    // DefaultWorkflowExecutor executor = new DefaultWorkflowExecutor(context);
    // executor.executeWorkflow();
    // if (!context.getWorkflowTrace().configuredLooksLikeActual()) {
    // collector.checkThat(" " + version.name() + ":" + suite.name() +
    // " failed.", false, is(true));
    // } else {
    // System.out.println("ok");
    // }
    // }

}
