/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.modifiablevariable.util.BadRandom;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.util.BasicTlsServer;
import de.rub.nds.tlsattacker.core.util.KeyStoreGenerator;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.recording.ClientRecordingTcpTransportHandler;
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
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;

public class RecordedWorkflowTest {

    private ClientRecordingTcpTransportHandler transportHandler;
    private KeyStore ks;
    private BasicTlsServer tlsServer;

    public RecordedWorkflowTest() {
    }

    @Before
    public void setUp() {
        RandomHelper.setRandom(new Random(0));
        TimeHelper.setProvider(new FixedTimeProvider(1000));
        try {
            KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024, new BadRandom());
            ks = KeyStoreGenerator.createKeyStore(k, new BadRandom());

            tlsServer = new BasicTlsServer(ks, KeyStoreGenerator.PASSWORD, "TLS", 4555);
        } catch (IOException | InvalidKeyException | KeyManagementException | KeyStoreException
                | NoSuchAlgorithmException | NoSuchProviderException | SignatureException | UnrecoverableKeyException
                | CertificateException | OperatorCreationException ex) {
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
    // TODO
    public void testFullWorkflowDeterminsitcWorkflow() throws IOException, NoSuchAlgorithmException, KeyStoreException,
            CertificateException, UnrecoverableKeyException, KeyManagementException, KeyManagementException,
            InvalidKeyException, NoSuchProviderException, SignatureException, OperatorCreationException,
            KeyManagementException {
        Config c = Config.createConfig();
        c.setDefaultSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        c.setDefaultClientSupportedCiphersuites(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        c.setWorkflowExecutorShouldOpen(false);
        WorkflowTrace trace = new WorkflowConfigurationFactory(c).createWorkflowTrace(WorkflowTraceType.FULL,
                RunningModeType.CLIENT);
        transportHandler = new ClientRecordingTcpTransportHandler(1000, "localhost", 4555);
        transportHandler.initialize();
        State state = new State(c, trace);
        state.getTlsContext().setTransportHandler(transportHandler);
        WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        try {
            executor.executeWorkflow();
        } catch (WorkflowExecutionException E) {
        }
        assertTrue(state.getWorkflowTrace().executedAsPlanned());
        state = new State(c);
        state.getTlsContext().setTransportHandler(transportHandler.getRecording().getPlayBackHandler());
        state.getTlsContext().getTransportHandler().initialize();
        executor = new DefaultWorkflowExecutor(state);
        try {
            executor.executeWorkflow();
        } catch (WorkflowExecutionException E) {
        }
        assertTrue(state.getWorkflowTrace().executedAsPlanned());
    }

}
