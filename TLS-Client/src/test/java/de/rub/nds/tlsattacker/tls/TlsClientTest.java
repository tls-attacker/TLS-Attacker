/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls;

import de.rub.nds.tlsattacker.tests.IntegrationTest;
import de.rub.nds.tlsattacker.tls.client.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.tls.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.constants.PublicKeyAlgorithm;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.message.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.util.KeyStoreGenerator;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTraceType;
import de.rub.nds.tlsattacker.tls.workflow.action.MessageActionFactory;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.ArrayConverter;
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
    @Category(IntegrationTest.class)
    public void testRSAWorkflows() throws OperatorCreationException {
        try {
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
    @Category(IntegrationTest.class)
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
        clientCommandConfig.getGeneralDelegate().setLogLevel(Level.INFO);
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
                config.setSupportedCiphersuites(cslist);
                if (config.getWorkflowTrace() != null) {
                    config.getWorkflowTrace().reset();
                }
                boolean result = testExecuteWorkflow(config);
                LOGGER.info("Testing: " + cs.name() + " Succes:" + result);
                collector.checkThat("" + cs.name() + " failed.", result, is(true));
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
        boolean result = isWorkflowTraceReasonable(tlsContext.getWorkflowTrace());
        if (!result) {
            LOGGER.log(Level.INFO, "Failed vanilla execution");
            LOGGER.info("PreMasterSecret:" + ArrayConverter.bytesToHexString(tlsContext.getPreMasterSecret()));
            LOGGER.info("MasterSecret:" + ArrayConverter.bytesToHexString(tlsContext.getMasterSecret()));
            LOGGER.info(workflowString);
            return result;
        }
        config.getWorkflowTrace().reset();
        config.getWorkflowTrace().makeGeneric();
        tlsContext = new TlsContext(config);
        workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(config.getExecutorType(), tlsContext);
        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException E) {
            E.printStackTrace();
        }
        workflowString = tlsContext.getWorkflowTrace().toString();
        result = isWorkflowTraceReasonable(tlsContext.getWorkflowTrace());
        if (!result) {
            LOGGER.log(Level.INFO, "Failed reset&generic execution");
            LOGGER.info("PreMasterSecret:" + ArrayConverter.bytesToHexString(tlsContext.getPreMasterSecret()));
            LOGGER.info("MasterSecret:" + ArrayConverter.bytesToHexString(tlsContext.getMasterSecret()));
            LOGGER.info(workflowString);

        }
        return result;
    }

    private boolean isWorkflowTraceReasonable(WorkflowTrace trace) {
        int counter = 0;
        for (ProtocolMessage configuredMessage : trace.getAllConfiguredMessages()) {
            if (counter >= trace.getAllExecutedMessages().size()) {
                return false;
            }
            ProtocolMessage receivedMessage = trace.getAllExecutedMessages().get(counter);
            if (configuredMessage.getClass().equals(ArbitraryMessage.class)) {
                break;
            }
            if (configuredMessage.getClass() != receivedMessage.getClass()) {
                if (configuredMessage.isRequired()) {
                    return false;
                }
            } else {
                counter++;
            }
        }
        return (!trace.getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.FINISHED).isEmpty());
    }

    private boolean testCustomWorkflow(int port) {
        ClientCommandConfig clientCommandConfig = new ClientCommandConfig(new GeneralDelegate());
        TlsConfig config = clientCommandConfig.createConfig();
        config.setHost("localhost:" + port);
        config.setTlsTimeout(TIMEOUT);
        config.setWorkflowTraceType(WorkflowTraceType.CLIENT_HELLO);

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

        return !(tlsContext.getWorkflowTrace()
                .getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.FINISHED).isEmpty());
    }

}
