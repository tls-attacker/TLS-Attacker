/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.modifiablevariable.util.BadRandom;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.util.BasicTlsServer;
import de.rub.nds.tlsattacker.core.util.KeyStoreGenerator;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.util.FixedTimeProvider;
import de.rub.nds.tlsattacker.util.TimeHelper;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class FindReceivedProtocolMessageActionTest {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final int SERVER_PORT = 48385;

    private final BadRandom random = new BadRandom(new Random(0), null);

    @BeforeAll
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /** Test of execute method, of class FindReceivedProtocolMessageAction. */
    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testExecute()
            throws NoSuchAlgorithmException,
                    CertificateException,
                    IOException,
                    KeyStoreException,
                    SignatureException,
                    InvalidKeyException,
                    NoSuchProviderException,
                    OperatorCreationException,
                    UnrecoverableKeyException,
                    KeyManagementException {
        Config config = Config.createConfig();
        config.getDefaultClientConnection().setPort(SERVER_PORT);

        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace =
                factory.createWorkflowTrace(WorkflowTraceType.HELLO, RunningModeType.CLIENT);
        FindReceivedProtocolMessageAction action_find_handshake =
                new FindReceivedProtocolMessageAction(ProtocolMessageType.HANDSHAKE);
        FindReceivedProtocolMessageAction action_find_app_data =
                new FindReceivedProtocolMessageAction(ProtocolMessageType.APPLICATION_DATA);
        trace.addTlsAction(action_find_handshake);
        trace.addTlsAction(action_find_app_data);

        State state = new State(config, trace);

        TimeHelper.setProvider(new FixedTimeProvider(0));
        KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024, random);
        KeyStore ks = KeyStoreGenerator.createKeyStore(k, random);
        BasicTlsServer tlsServer =
                new BasicTlsServer(ks, KeyStoreGenerator.PASSWORD, "TLS", SERVER_PORT);

        LOGGER.info("Starting test server");
        new Thread(tlsServer).start();
        while (!tlsServer.isInitialized())
            ;

        WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        executor.executeWorkflow();

        LOGGER.info("Killing server...");
        tlsServer.shutdown();
        LOGGER.info("Done.");

        assertTrue(action_find_handshake.isFound());
        assertFalse(action_find_app_data.isFound());
    }
}
