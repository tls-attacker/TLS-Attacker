/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.client.main;

import de.rub.nds.modifiablevariable.util.BadRandom;
import de.rub.nds.tlsattacker.client.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.TimeoutDelegate;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.PublicKeyAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.util.BasicTlsServer;
import de.rub.nds.tlsattacker.core.util.KeyStoreGenerator;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.MessageActionFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
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
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.fail;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.rules.ErrorCollector;

public class TlsClientTest {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final int TIMEOUT = 2000;

    private final BadRandom random = new BadRandom(new Random(0), null);

    @Rule
    public ErrorCollector collector = new ErrorCollector();

    private BasicTlsServer tlsServer;

    public TlsClientTest() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    @Category(IntegrationTests.class)
    public void testRSAWorkflows() throws OperatorCreationException {
        try {
            TimeHelper.setProvider(new FixedTimeProvider(0));
            KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024, random);
            KeyStore ks = KeyStoreGenerator.createKeyStore(k, random);
            tlsServer = new BasicTlsServer(ks, KeyStoreGenerator.PASSWORD, "TLS", 0);
            new Thread(tlsServer).start();
            while (!tlsServer.isInitialized())
                ;
            CONSOLE.info("Testing RSA");
            testExecuteWorkflows(PublicKeyAlgorithm.RSA, tlsServer.getPort());
            tlsServer.shutdown();
        } catch (NoSuchAlgorithmException | CertificateException | IOException | InvalidKeyException
                | KeyStoreException | NoSuchProviderException | SignatureException | UnrecoverableKeyException
                | KeyManagementException ex) {
            LOGGER.warn(ex);
            fail();
        }
    }

    @Test
    @Category(IntegrationTests.class)
    public void testECWorkflows() throws OperatorCreationException {
        try {
            KeyPair k = KeyStoreGenerator.createECKeyPair(256, random);
            KeyStore ks = KeyStoreGenerator.createKeyStore(k, random);
            tlsServer = new BasicTlsServer(ks, KeyStoreGenerator.PASSWORD, "TLS", 0);
            new Thread(tlsServer).start();
            while (!tlsServer.isInitialized())
                ;
            CONSOLE.info("Testing EC");
            testExecuteWorkflows(PublicKeyAlgorithm.EC, tlsServer.getPort());
            tlsServer.shutdown();
        } catch (NoSuchAlgorithmException | KeyStoreException | IOException | CertificateException
                | UnrecoverableKeyException | KeyManagementException | InvalidKeyException | NoSuchProviderException
                | SignatureException ex) {
            LOGGER.warn(ex);
            fail(); // Todo
        }
    }

    /**
     * Test of executeWorkflow method, of class WorkflowExecutor.
     *
     * @param algorithm
     * @param port
     */
    public void testExecuteWorkflows(PublicKeyAlgorithm algorithm, int port) {
        ClientCommandConfig clientCommandConfig = new ClientCommandConfig(new GeneralDelegate());
        TimeoutDelegate timeoutDelegate = (TimeoutDelegate) clientCommandConfig.getDelegate(TimeoutDelegate.class);
        timeoutDelegate.setTimeout(TIMEOUT);
        ClientDelegate clientDelegate = (ClientDelegate) clientCommandConfig.getDelegate(ClientDelegate.class);
        clientDelegate.setHost("localhost:" + port);
        Config config = clientCommandConfig.createConfig();
        config.setEnforceSettings(false);
        List<String> serverList = Arrays.asList(tlsServer.getCipherSuites());
        config.setHighestProtocolVersion(ProtocolVersion.SSL3);
        testProtocolCompatibility(serverList, config, algorithm);
        config.setHighestProtocolVersion(ProtocolVersion.TLS10);
        testProtocolCompatibility(serverList, config, algorithm);
        config.setHighestProtocolVersion(ProtocolVersion.TLS11);
        testProtocolCompatibility(serverList, config, algorithm);
        config.setHighestProtocolVersion(ProtocolVersion.TLS12);
        testProtocolCompatibility(serverList, config, algorithm);

        if (algorithm == PublicKeyAlgorithm.RSA) {
            boolean result = testCustomWorkflow(port);
            collector.checkThat("Custom failed.", result, is(true));
        }

    }

    private void testProtocolCompatibility(List<String> serverList, Config config, PublicKeyAlgorithm algorithm) {
        LOGGER.info(config.getHighestProtocolVersion());
        for (CipherSuite cs : CipherSuite.getImplemented()) {
            if (cs.name().toUpperCase().contains("NULL") || cs.name().toUpperCase().contains("ANON")) {
                continue;
            }
            Set<PublicKeyAlgorithm> requiredAlgorithms = AlgorithmResolver.getRequiredKeystoreAlgorithms(cs);
            requiredAlgorithms.remove(algorithm);
            final boolean serverSupportsCipherSuite = serverList.contains(cs.toString());
            final boolean cipherSuiteIsSupportedByProtocolVersion = cs.isSupportedInProtocol(config
                    .getHighestProtocolVersion());
            if (serverSupportsCipherSuite && cipherSuiteIsSupportedByProtocolVersion && requiredAlgorithms.isEmpty()) {
                LinkedList<CipherSuite> cslist = new LinkedList<>();
                cslist.add(cs);
                config.setDefaultClientSupportedCiphersuites(cslist);
                config.setDefaultSelectedCipherSuite(cs);
                boolean result = testExecuteWorkflow(config);
                CONSOLE.info("Testing " + config.getHighestProtocolVersion().name() + ": " + cs.name() + " Succes:"
                        + result);
                collector.checkThat(" " + config.getHighestProtocolVersion().name() + ":" + cs.name() + " failed.",
                        result, is(true));
            }
        }
    }

    private boolean testExecuteWorkflow(Config config) {
        config.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
        State state = new State(config);

        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                config.getWorkflowExecutorType(), state);

        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException E) {
            LOGGER.error(E);
            fail();

        }

        String workflowString = state.getWorkflowTrace().toString();
        boolean result = state.getWorkflowTrace().executedAsPlanned();

        if (!result) {
            LOGGER.info(workflowString);
            return result;
        }
        return result;
    }

    private boolean testCustomWorkflow(int port) {
        ClientCommandConfig clientCommandConfig = new ClientCommandConfig(new GeneralDelegate());
        TimeoutDelegate timeoutDelegate = (TimeoutDelegate) clientCommandConfig.getDelegate(TimeoutDelegate.class);
        timeoutDelegate.setTimeout(TIMEOUT);
        ClientDelegate clientDelegate = (ClientDelegate) clientCommandConfig.getDelegate(ClientDelegate.class);
        clientDelegate.setHost("localhost:" + port);
        Config config = clientCommandConfig.createConfig();

        AliasedConnection con = config.getDefaultClientConnection();
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(MessageActionFactory.createAction(con, ConnectionEndType.CLIENT, new ClientHelloMessage(
                config)));
        trace.addTlsAction(MessageActionFactory.createAction(con, ConnectionEndType.SERVER, new ServerHelloMessage(
                config), new CertificateMessage(config), new ServerHelloDoneMessage(config)));

        trace.addTlsAction(MessageActionFactory.createAction(con, ConnectionEndType.CLIENT,
                new RSAClientKeyExchangeMessage(config), new ChangeCipherSpecMessage(config), new FinishedMessage(
                        config)));
        trace.addTlsAction(MessageActionFactory.createAction(con, ConnectionEndType.SERVER,
                new ChangeCipherSpecMessage(config), new FinishedMessage(config)));

        State state = new State(config, trace);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                config.getWorkflowExecutorType(), state);
        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException E) {
            return false;
        }

        return trace.executedAsPlanned();
    }
}
