/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.client;

import de.rub.nds.tlsattacker.client.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
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
import de.rub.nds.tlsattacker.core.util.KeyStoreGenerator;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.core.workflow.action.MessageActionFactory;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
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
import java.util.Set;
import org.apache.logging.log4j.Level;
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

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class TlsClientTest {

    private static final Logger LOGGER = LogManager.getLogger(TlsClientTest.class);

    private static final int PORT = 4433;

    private static final int TIMEOUT = 2000;

    @Rule
    public ErrorCollector collector = new ErrorCollector();

    private TLSServer tlsServer;

    public TlsClientTest() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    @Category(IntegrationTests.class)
    public void testRSAWorkflows() throws OperatorCreationException {
        try {
            TimeHelper.setProvider(new FixedTimeProvider(0));
            KeyPair k = KeyStoreGenerator.createRSAKeyPair(1024);
            KeyStore ks = KeyStoreGenerator.createKeyStore(k);
            tlsServer = new TLSServer(ks, KeyStoreGenerator.PASSWORD, "TLS", PORT);
            new Thread(tlsServer).start();
            while (!tlsServer.isInitialized())
                ;
            LOGGER.log(Level.INFO, "Testing RSA");
            testExecuteWorkflows(PublicKeyAlgorithm.RSA, PORT);
            tlsServer.shutdown();
        } catch (NoSuchAlgorithmException | CertificateException | IOException | InvalidKeyException
                | KeyStoreException | NoSuchProviderException | SignatureException | UnrecoverableKeyException
                | KeyManagementException ex) {
            ex.printStackTrace();
            fail();
        }
    }

    @Test
    @Category(IntegrationTests.class)
    public void testECWorkflows() throws OperatorCreationException {
        try {
            KeyPair k = KeyStoreGenerator.createECKeyPair(256);
            KeyStore ks = KeyStoreGenerator.createKeyStore(k);
            tlsServer = new TLSServer(ks, KeyStoreGenerator.PASSWORD, "TLS", PORT + 1);
            new Thread(tlsServer).start();
            while (!tlsServer.isInitialized())
                ;
            LOGGER.log(Level.INFO, "Testing EC");
            testExecuteWorkflows(PublicKeyAlgorithm.EC, PORT + 1);
            tlsServer.shutdown();
        } catch (NoSuchAlgorithmException | KeyStoreException | IOException | CertificateException
                | UnrecoverableKeyException | KeyManagementException | InvalidKeyException | NoSuchProviderException
                | SignatureException ex) {
            ex.printStackTrace();
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
        clientCommandConfig.getGeneralDelegate().setLogLevel(Level.DEBUG);
        TlsConfig config = clientCommandConfig.createConfig();
        config.setHost("localhost:" + port);
        config.setTlsTimeout(TIMEOUT);
        List<String> serverList = Arrays.asList(tlsServer.getCipherSuites());
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

    private void testProtocolCompatibility(List<String> serverList, TlsConfig config, PublicKeyAlgorithm algorithm) {
        LOGGER.info(config.getHighestProtocolVersion());
        for (CipherSuite cs : CipherSuite.getImplemented()) {
            Set<PublicKeyAlgorithm> requiredAlgorithms = AlgorithmResolver.getRequiredKeystoreAlgorithms(cs);
            requiredAlgorithms.remove(algorithm);
            if (serverList.contains(cs.toString()) && cs.isSupportedInProtocol(config.getHighestProtocolVersion())
                    && requiredAlgorithms.isEmpty()) {
                LinkedList<CipherSuite> cslist = new LinkedList<>();
                cslist.add(cs);
                config.setDefaultClientSupportedCiphersuites(cslist);
                config.setWorkflowTrace(null);
                boolean result = testExecuteWorkflow(config);
                LOGGER.info("Testing " + config.getHighestProtocolVersion().name() + ": " + cs.name() + " Succes:"
                        + result);
                collector.checkThat(" " + config.getHighestProtocolVersion().name() + ":" + cs.name() + " failed.",
                        result, is(true));
            }
        }
    }

    private boolean testExecuteWorkflow(TlsConfig config) {
        config.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
        TlsContext tlsContext = new TlsContext(config);

        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(config.getExecutorType(),
                tlsContext);
        try {
            workflowExecutor.executeWorkflow();
        } catch (Exception E) {
            E.printStackTrace();
        }
        String workflowString = tlsContext.getWorkflowTrace().toString();
        boolean result = tlsContext.getWorkflowTrace().configuredLooksLikeActual();
        if (!result) {
            LOGGER.info(workflowString);
            return result;
        }
        return result;
    }

    private boolean testCustomWorkflow(int port) {
        ClientCommandConfig clientCommandConfig = new ClientCommandConfig(new GeneralDelegate());
        clientCommandConfig.getGeneralDelegate().setLogLevel(Level.INFO);
        TlsConfig config = clientCommandConfig.createConfig();
        config.setHost("localhost:" + port);
        config.setTlsTimeout(TIMEOUT);
        config.setWorkflowTraceType(WorkflowTraceType.HELLO);

        TlsContext tlsContext = new TlsContext(config);
        config.setWorkflowTrace(new WorkflowTrace());

        WorkflowTrace trace = config.getWorkflowTrace();
        trace.add(MessageActionFactory.createAction(ConnectionEnd.CLIENT, ConnectionEnd.CLIENT, new ClientHelloMessage(
                config)));
        trace.add(MessageActionFactory.createAction(ConnectionEnd.CLIENT, ConnectionEnd.SERVER, new ServerHelloMessage(
                config), new CertificateMessage(config), new ServerHelloDoneMessage(config)));

        trace.add(MessageActionFactory.createAction(ConnectionEnd.CLIENT, ConnectionEnd.CLIENT,
                new RSAClientKeyExchangeMessage(config), new ChangeCipherSpecMessage(config), new FinishedMessage(
                        config)));
        trace.add(MessageActionFactory.createAction(ConnectionEnd.CLIENT, ConnectionEnd.SERVER,
                new ChangeCipherSpecMessage(config), new FinishedMessage(config)));
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(config.getExecutorType(),
                tlsContext);
        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException E) {
            return false;
        }

        return trace.configuredLooksLikeActual();
    }

}
