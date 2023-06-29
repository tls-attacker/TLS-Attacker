/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow;

import static org.junit.jupiter.api.Assertions.assertTrue;

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
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Random;
import java.util.logging.Logger;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class RecordedWorkflowTest {

    private BasicTlsServer tlsServer;

    @BeforeEach
    public void setUp() {
        RandomHelper.setRandom(new Random(0));
        TimeHelper.setProvider(new FixedTimeProvider(1000));
        try {
            KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024, new BadRandom());
            KeyStore ks = KeyStoreGenerator.createKeyStore(k, new BadRandom());

            tlsServer = new BasicTlsServer(ks, KeyStoreGenerator.PASSWORD, "TLS", 4555);
        } catch (IOException
                | InvalidKeyException
                | KeyManagementException
                | KeyStoreException
                | NoSuchAlgorithmException
                | NoSuchProviderException
                | SignatureException
                | UnrecoverableKeyException
                | CertificateException
                | OperatorCreationException ex) {
            Logger.getLogger(RecordedWorkflowTest.class.getName())
                    .log(java.util.logging.Level.SEVERE, null, ex);
        }
        tlsServer.start();
        while (!tlsServer.isInitialized())
            ;
    }

    @AfterEach
    public void tearDown() {
        tlsServer.shutdown();
    }

    /**
     * Test of executeWorkflow method, of class DefaultWorkflowExecutor.
     *
     * @throws java.io.IOException
     */
    @Test
    @Disabled("Not implemented")
    public void testFullWorkflowDeterministicWorkflow() throws IOException {
        Config c = Config.createConfig();
        c.setDefaultSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        c.setDefaultClientSupportedCipherSuites(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        c.setWorkflowExecutorShouldOpen(false);
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(c)
                        .createWorkflowTrace(WorkflowTraceType.FULL, RunningModeType.CLIENT);
        ClientRecordingTcpTransportHandler transportHandler =
                new ClientRecordingTcpTransportHandler(1000, 1000, "localhost", 4555);
        transportHandler.initialize();
        State state = new State(c, trace);
        state.getTcpContext().setTransportHandler(transportHandler);
        WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        try {
            executor.executeWorkflow();
        } catch (WorkflowExecutionException E) {
        }
        assertTrue(state.getWorkflowTrace().executedAsPlanned());
        state = new State(c);
        state.getTcpContext()
                .setTransportHandler(transportHandler.getRecording().getPlayBackHandler());
        state.getContext().getTransportHandler().initialize();
        executor = new DefaultWorkflowExecutor(state);
        try {
            executor.executeWorkflow();
        } catch (WorkflowExecutionException E) {
        }
        assertTrue(state.getWorkflowTrace().executedAsPlanned());
    }
}
