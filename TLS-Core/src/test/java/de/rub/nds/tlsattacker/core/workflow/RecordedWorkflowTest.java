/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.util.BasicTlsServer;
import de.rub.nds.tlsattacker.core.util.KeyStoreGenerator;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.recording.ClientRecordingTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.recording.RecordedLine;
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
import java.util.Random;
import java.util.logging.Logger;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.config.Configurator;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class RecordedWorkflowTest {

    private ClientRecordingTcpTransportHandler transportHandler;
    private KeyStore ks;
    private BasicTlsServer tlsServer;

    public RecordedWorkflowTest() {
    }

    @Before
    public void setUp() {
        RandomHelper.setRandom(new Random(0));
        Configurator.setRootLevel(Level.INFO);
        TimeHelper.setProvider(new FixedTimeProvider(1000));
        try {
            KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024);
            ks = KeyStoreGenerator.createKeyStore(k);

            tlsServer = new BasicTlsServer(ks, KeyStoreGenerator.PASSWORD, "TLS", 4555);
        } catch (Exception ex) {
            Logger.getLogger(RecordedWorkflowTest.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        tlsServer.start();
        do {
        } while (!tlsServer.isInitialized());
    }

    @After
    public void tearDown() {
        tlsServer.shutdown();
    }

    /**
     * Test of executeWorkflow method, of class DefaultWorkflowExecutor.
     *
     * @throws java.io.IOException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.KeyManagementException
     * @throws java.security.cert.CertificateException
     * @throws java.security.KeyStoreException
     * @throws java.security.UnrecoverableKeyException
     * @throws java.security.InvalidKeyException
     * @throws org.bouncycastle.operator.OperatorCreationException
     * @throws java.security.NoSuchProviderException
     * @throws java.security.SignatureException
     */
    @Test
    public void testFullWorkflowDeterminsitcWorkflow() throws IOException, NoSuchAlgorithmException, KeyStoreException,
            CertificateException, UnrecoverableKeyException, KeyManagementException, KeyManagementException,
            InvalidKeyException, NoSuchProviderException, SignatureException, OperatorCreationException,
            KeyManagementException {
        Config c = Config.createConfig();
        c.setDefaultSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        c.setDefaultClientSupportedCiphersuites(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        c.setPort(4555);
        c.setHost("127.0.0.1");
        c.setWorkflowExecutorShouldOpen(false);
        c.setWorkflowTraceType(WorkflowTraceType.FULL);
        transportHandler = new ClientRecordingTcpTransportHandler(1000, "localhost", 4555);
        transportHandler.initialize();
        TlsContext context = new TlsContext(c);
        context.setTransportHandler(transportHandler);
        WorkflowExecutor executor = new DefaultWorkflowExecutor(context);
        try {
            executor.executeWorkflow();
        } catch (Exception E) {
            E.printStackTrace();
        }
        assertTrue(context.getWorkflowTrace().executedAsPlanned());
        context = new TlsContext(c);
        context.setTransportHandler(transportHandler.getRecording().getPlayBackHandler());
        context.getTransportHandler().initialize();
        executor = new DefaultWorkflowExecutor(context);
        try {
            executor.executeWorkflow();
        } catch (Exception E) {
            E.printStackTrace();
        }
        assertTrue(context.getWorkflowTrace().executedAsPlanned());
    }

}
