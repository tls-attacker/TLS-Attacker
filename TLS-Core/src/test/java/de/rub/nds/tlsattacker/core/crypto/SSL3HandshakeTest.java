/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.modifiablevariable.util.RandomHelper;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.util.BasicTlsServer;
import de.rub.nds.tlsattacker.core.util.KeyStoreGenerator;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.ClientConnectionEnd;
import de.rub.nds.tlsattacker.transport.ServerConnectionEnd;
import de.rub.nds.tlsattacker.util.FixedTimeProvider;
import de.rub.nds.tlsattacker.util.KeystoreHandler;
import de.rub.nds.tlsattacker.util.TimeHelper;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.logging.Level;
import org.bouncycastle.operator.OperatorCreationException;

/**
 * @author Felix Kleine-Wilde <felix.kleine-wilde@rub.de>
 */
public class SSL3HandshakeTest {

    private static final Logger LOGGER = LogManager.getLogger(SSL3HandshakeTest.class.getName());
    private static final Provider BC_PROVIDER = new BouncyCastleProvider();
    private static final int TEST_PORT = 12345;
    private static final ProtocolVersion VERSION = ProtocolVersion.SSL3;
    private static final CipherSuite SUITE = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA;

    private static final TrustManager[] TRUSTALL_TRUSTMANAGER = new TrustManager[] { new X509TrustManager() {
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

        public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
        }

        public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
        }
    } };

    private static String backupDisabledAlgorithmsProperty;

    private Config config;
    private BasicTlsServer tlsServer;

    public SSL3HandshakeTest() {
    }

    @BeforeClass
    public static void setUpClass() {
        // System.setProperty("javax.net.debug", "all");
        backupDisabledAlgorithmsProperty = Security.getProperty("jdk.tls.disabledAlgorithms");
        Security.addProvider(BC_PROVIDER);
        Security.setProperty("jdk.tls.disabledAlgorithms", "");
    }

    @AfterClass
    public static void tearDownClass() {
        Security.addProvider(BC_PROVIDER);
        Security.setProperty("jdk.tls.disabledAlgorithms", backupDisabledAlgorithmsProperty);
    }

    @Before
    public void setUp() {
        config = Config.createConfig();
        config.setHighestProtocolVersion(VERSION);
        config.setStopActionsAfterFatal(false);
        config.setClientAuthentication(false);
        config.setRecordLayerType(RecordLayerType.RECORD);
        config.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
        config.clearConnectionEnds();
    }

    @After
    public void tearDown() {
        config = null;
    }

    @Test
    public void testClientHandshake() throws IOException {
        config.addConnectionEnd(new ClientConnectionEnd("client", TEST_PORT, "localhost"));

        final State state = new State(config);
        final WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                config.getWorkflowExecutorType(), state);

        setupContext(state);
        try {
            setupServer(false);
            checkWorkflow(workflowExecutor, state);
        } catch (IOException | InvalidKeyException | KeyManagementException | KeyStoreException
                | NoSuchAlgorithmException | NoSuchProviderException | SignatureException | UnrecoverableKeyException
                | CertificateException | OperatorCreationException E) {
        } finally {
            if (tlsServer != null) {
                tlsServer.shutdown();
            }
        }
    }

    @Test
    @Ignore("Client Authentication not fully supported yet.")
    public void testClientHandshakeWithClientAuthentication() throws IOException {
        config.addConnectionEnd(new ClientConnectionEnd("client", TEST_PORT, "localhost"));
        config.setClientAuthentication(true);

        final State state = new State(config);
        final WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                config.getWorkflowExecutorType(), state);
        setupContext(state);
        try {
            setupServer(true);
            checkWorkflow(workflowExecutor, state);
        } catch (IOException | InvalidKeyException | KeyManagementException | KeyStoreException
                | NoSuchAlgorithmException | NoSuchProviderException | SignatureException | UnrecoverableKeyException
                | CertificateException | OperatorCreationException E) {
        } finally {
            if (tlsServer != null) {
                tlsServer.shutdown();
            }

        }
    }

    @Test
    public void testServerHandshake() {
        config.addConnectionEnd(new ServerConnectionEnd(Config.DEFAULT_CONNECTION_END_ALIAS, TEST_PORT));
        final State state = new State(config);
        final WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                config.getWorkflowExecutorType(), state);
        setupContext(state);
        setupClient();
        checkWorkflow(workflowExecutor, state);
    }

    @Test
    @Ignore("Client Authentication not fully supported yet.")
    public void testServerHandshakeWithClientAuthentication() {
        config.addConnectionEnd(new ServerConnectionEnd(Config.DEFAULT_CONNECTION_END_ALIAS, TEST_PORT));
        config.setClientAuthentication(true);

        final State state = new State(config);
        final WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                config.getWorkflowExecutorType(), state);

        setupContext(state);
        setupClient();
        checkWorkflow(workflowExecutor, state);
    }

    private TlsContext setupContext(State state) {
        final TlsContext context = state.getTlsContext();
        context.setClientSupportedProtocolVersions(VERSION);
        context.setClientSupportedCiphersuites(SUITE);
        context.setSelectedCipherSuite(SUITE);
        context.setSelectedProtocolVersion(VERSION);
        return context;
    }

    private void checkWorkflow(WorkflowExecutor workflowExecutor, State state) {
        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException e) {
            Assert.fail(e.getMessage());
        }
        final String workflowString = state.getWorkflowTrace().toString();
        final boolean result = state.getWorkflowTrace().executedAsPlanned();
        if (result) {
            LOGGER.debug("Workflow executed as planned!");
        } else {
            Assert.fail(workflowString);
        }
    }

    private void setupClient() {
        new Thread() {
            @Override
            public void run() {
                final SSLSocketFactory factory = getSSLContext().getSocketFactory();
                try (final SSLSocket socket = (SSLSocket) factory.createSocket()) {
                    socket.connect(new InetSocketAddress("localhost", TEST_PORT), 1000);
                    configureSocket(socket);
                    socket.startHandshake();
                    readInput(socket);
                } catch (IOException e) {
                    handleIOException(e);
                }
            }
        }.start();
    }

    private void setupServer(final boolean clientAuth) throws CertificateException, IOException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, KeyStoreException,
            SignatureException, OperatorCreationException, UnrecoverableKeyException, KeyManagementException {
        TimeHelper.setProvider(new FixedTimeProvider(0));
        KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024, RandomHelper.getBadSecureRandom());
        KeyStore ks = KeyStoreGenerator.createKeyStore(k, RandomHelper.getBadSecureRandom());
        tlsServer = new BasicTlsServer(ks, KeyStoreGenerator.PASSWORD, "SSLv3", TEST_PORT);
        new Thread(tlsServer).start();
        while (!tlsServer.isInitialized())
            ;
    }

    private static void configureSocket(SSLSocket socket) {
        socket.setEnabledProtocols(new String[] { toJavaName(VERSION) });
        socket.setEnabledCipherSuites(new String[] { SUITE.toString() });
    }

    private static void handleIOException(IOException e) {
        final String failMessage = "Unexpected IOException while Testing" + e.getMessage();
        LOGGER.debug(failMessage, e);
        Assert.fail(failMessage);
    }

    private SSLContext getSSLContext() {
        try {
            final SSLContext sc = SSLContext.getInstance("SSL");
            final KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            final FileInputStream fin = new FileInputStream(new File("").getAbsolutePath().concat(
                    File.separator + "src" + File.separator + "main" + File.separator + "resources" + File.separator
                            + "default.jks"));
            final KeyStore ks = KeystoreHandler.loadKeyStore(fin, "password");
            kmf.init(ks, "password".toCharArray());
            sc.init(kmf.getKeyManagers(), TRUSTALL_TRUSTMANAGER, new java.security.SecureRandom());
            return sc;
        } catch (NoSuchAlgorithmException | KeyManagementException | KeyStoreException | CertificateException
                | IOException | UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private static void readInput(Socket socket) throws IOException {
        final BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        String inputLine;
        while ((inputLine = in.readLine()) != null) {
            LOGGER.debug(inputLine);
        }
    }

    private static String toJavaName(ProtocolVersion version) {
        switch (version) {
            case SSL3:
                return "SSLv3";
            case TLS10:
                return "TLSv1";
            case TLS11:
                return "TLSv1.1";
            case TLS12:
                return "TLSv1.2";
            default:
                throw new IllegalArgumentException(version.toString() + " not supported");
        }
    }
}
