/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.factory;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.HttpsResponseMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.protocol.message.PSKClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PSKDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PSKRSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PSKDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PSKECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PSKECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SRPClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SRPServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.MessageActionFactory;
import de.rub.nds.tlsattacker.core.workflow.action.RenegotiationAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.TLSAction;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class WorkflowConfigurationFactory {

    static final Logger LOGGER = LogManager.getLogger(WorkflowConfigurationFactory.class);

    protected final Config config;

    public WorkflowConfigurationFactory(Config config) {
        this.config = config;
    }

    public WorkflowTrace createWorkflowTrace(WorkflowTraceType type) {
        switch (type) {
            case HELLO:
                return createHelloWorkflow();
            case FULL:
                return createFullWorkflow();
            case HANDSHAKE:
                return createHandshakeWorkflow();
            case SHORT_HELLO:
                return createShortHelloWorkflow();
            case SSL2_HELLO:
                return createSsl2HelloWorkflow();
            case CLIENT_RENEGOTIATION:
                return createClientRenegotiationWorkflow();
            case SERVER_RENEGOTIATION:
                return createServerRenegotiationWorkflow();
            case HTTPS:
                return createHttpsWorkflow();
            case RESUMPTION:
                return createResumptionWorkflow();
            case FULL_RESUMPTION:
                return createFullResumptionWorkflow();
        }
        throw new ConfigurationException("Unknown WorkflowTraceType " + type.name());
    }

    private ConnectionEnd getSafeSingleContextConnectionEnd() {
        // Let's be explicit here
        if (config.getConnectionEnds().size() != 1) {
            throw new ConfigurationException("This workflow type can only be created for"
                    + " a single context, but multiple contexts are defined in the config.");
        }
        return config.getConnectionEnd();
    }

    /**
     * Create a hello workflow for the default connection end defined in config.
     */
    public WorkflowTrace createHelloWorkflow() {
        return createHelloWorkflow(getSafeSingleContextConnectionEnd());
    }
    
/**
     * Create a hello workflow for the given connection end.
     */
    private WorkflowTrace createHelloWorkflow(ConnectionEnd ourConnectionEnd) {
        WorkflowTrace workflowTrace = new WorkflowTrace(config);

        List<ProtocolMessage> messages = new LinkedList<>();
        ClientHelloMessage clientHello = null;
        if (config.getHighestProtocolVersion() == ProtocolVersion.DTLS10
                || config.getHighestProtocolVersion() == ProtocolVersion.DTLS12) {
            clientHello = new ClientHelloMessage(config);
            clientHello.setIncludeInDigest(false);
        } else {
            clientHello = new ClientHelloMessage(config);
        }
        messages.add(clientHello);

        workflowTrace.addTlsAction(MessageActionFactory.createAction(ourConnectionEnd, ConnectionEndType.CLIENT,
                messages));
        if (config.getHighestProtocolVersion() == ProtocolVersion.DTLS10
                || config.getHighestProtocolVersion() == ProtocolVersion.DTLS12) {

            HelloVerifyRequestMessage helloVerifyRequestMessage = new HelloVerifyRequestMessage(config);
            helloVerifyRequestMessage.setIncludeInDigest(false);
            messages = new LinkedList<>();

            messages.add(helloVerifyRequestMessage);
            workflowTrace.addTlsAction(MessageActionFactory.createAction(ourConnectionEnd, ConnectionEndType.SERVER,
                    messages));
            clientHello = new ClientHelloMessage(config);
            messages = new LinkedList<>();
            messages.add(clientHello);
            workflowTrace.addTlsAction(MessageActionFactory.createAction(ourConnectionEnd, ConnectionEndType.CLIENT,
                    messages));
        }
        messages = new LinkedList<>();
        messages.add(new ServerHelloMessage(config));

        if (config.getHighestProtocolVersion().isTLS13()) {
            messages.add(new EncryptedExtensionsMessage(config));
            if (config.isClientAuthentication()) {
                CertificateRequestMessage certRequest = new CertificateRequestMessage(config);
                messages.add(certRequest);
            }
            if (ourConnectionEnd.getConnectionEndType() == ConnectionEndType.CLIENT) {
                messages.add(new CertificateMessage());
            } else {
                messages.add(new CertificateMessage(config));
            }
            messages.add(new CertificateVerifyMessage(config));
            messages.add(new FinishedMessage(config));
        } else {
            if (ourConnectionEnd.getConnectionEndType() == ConnectionEndType.CLIENT) {
                messages.add(new CertificateMessage());
            } else {
                messages.add(new CertificateMessage(config));
            }
            if (config.getDefaultSelectedCipherSuite().isEphemeral()) {
                addServerKeyExchangeMessage(messages);
            }
            if (config.isClientAuthentication()) {
                CertificateRequestMessage certRequest = new CertificateRequestMessage(config);
                messages.add(certRequest);
            }
            messages.add(new ServerHelloDoneMessage(config));
        }
        workflowTrace.addTlsAction(MessageActionFactory.createAction(ourConnectionEnd, ConnectionEndType.SERVER,
                messages));

        return workflowTrace;
}

       /**
     * Create a handshake workflow for the default connection end defined in
     * config.
     */
    public WorkflowTrace createHandshakeWorkflow() {
        return createHandshakeWorkflow(getSafeSingleContextConnectionEnd());
    }

    /**
     * Create a hello workflow for the given connection end.
     */
    private WorkflowTrace createHandshakeWorkflow(ConnectionEnd ourConnectionEnd) {

        WorkflowTrace workflowTrace = this.createHelloWorkflow(ourConnectionEnd);
        List<ProtocolMessage> messages = new LinkedList<>();
        if (config.getHighestProtocolVersion().isTLS13()) {
            if (config.isClientAuthentication()) {
                messages.add(new CertificateMessage(config));
                messages.add(new CertificateVerifyMessage(config));
            }
        } else {
            if (config.isClientAuthentication()) {
                messages.add(new CertificateMessage(config));
                addClientKeyExchangeMessage(messages);
                messages.add(new CertificateVerifyMessage(config));
            } else {
                addClientKeyExchangeMessage(messages);
            }
            messages.add(new ChangeCipherSpecMessage(config));
        }
        messages.add(new FinishedMessage(config));
        workflowTrace.addTlsAction(MessageActionFactory.createAction(ourConnectionEnd, ConnectionEndType.CLIENT,
                messages));
        if (!config.getHighestProtocolVersion().isTLS13()) {
            messages = new LinkedList<>();
            messages.add(new ChangeCipherSpecMessage(config));
            messages.add(new FinishedMessage(config));

            workflowTrace.addTlsAction(MessageActionFactory.createAction(ourConnectionEnd, ConnectionEndType.SERVER,
                    messages));
        }

        return workflowTrace;
        }
    
    private void addClientKeyExchangeMessage(List<ProtocolMessage> messages) {
        CipherSuite cs = config.getDefaultSelectedCipherSuite();
        KeyExchangeAlgorithm algorithm = AlgorithmResolver.getKeyExchangeAlgorithm(cs);
        if (algorithm != null) {

            switch (algorithm) {
                case RSA:
                    messages.add(new RSAClientKeyExchangeMessage(config));
                    break;
                case ECDHE_ECDSA:
                case ECDH_ECDSA:
                case ECDH_RSA:
                case ECDHE_RSA:
                    messages.add(new ECDHClientKeyExchangeMessage(config));
                    break;
                case DHE_DSS:
                case DHE_RSA:
                case DH_ANON:
                case DH_DSS:
                case DH_RSA:
                    messages.add(new DHClientKeyExchangeMessage(config));
                    break;
                case PSK:
                    messages.add(new PSKClientKeyExchangeMessage(config));
                    break;
                case DHE_PSK:
                    messages.add(new PSKDHClientKeyExchangeMessage(config));
                    break;
                case ECDHE_PSK:
                    messages.add(new PSKECDHClientKeyExchangeMessage(config));
                    break;
                case RSA_PSK:
                    messages.add(new PSKRSAClientKeyExchangeMessage(config));
                    break;
                case SRP_SHA_DSS:
                case SRP_SHA_RSA:
                case SRP_SHA:
                    messages.add(new SRPClientKeyExchangeMessage(config));
                    break;
                default:
                    LOGGER.warn("Unsupported key exchange algorithm: " + algorithm
                            + ", not adding ClientKeyExchange Message");
                    break;
            }
        } else {
            LOGGER.warn("Unsupported key exchange algorithm: " + algorithm + ", not adding ClientKeyExchange Message");
        }
    }

    private void addServerKeyExchangeMessage(List<ProtocolMessage> messages) {
        CipherSuite cs = config.getDefaultSelectedCipherSuite();
        if (cs.isEphemeral()) {
            switch (AlgorithmResolver.getKeyExchangeAlgorithm(cs)) {
                case ECDHE_ECDSA:
                case ECDHE_RSA:
                    messages.add(new ECDHEServerKeyExchangeMessage(config));
                    break;
                case DHE_DSS:
                case DHE_RSA:
                    messages.add(new DHEServerKeyExchangeMessage(config));
                    break;
                case DHE_PSK:
                    messages.add(new PSKDHEServerKeyExchangeMessage(config));
                    break;
                case ECDHE_PSK:
                    messages.add(new PSKECDHEServerKeyExchangeMessage(config));
                    break;
                case SRP_SHA_DSS:
                case SRP_SHA_RSA:
                case SRP_SHA:
                    messages.add(new SRPServerKeyExchangeMessage(config));
                    break;
                default:
                    LOGGER.warn("Unsupported key exchange algorithm: " + AlgorithmResolver.getKeyExchangeAlgorithm(cs)
                            + ", not adding ServerKeyExchange Message");
                    break;
            }
        } else {
            LOGGER.debug("Not adding ServerKeyExchange message - " + cs.name() + " is not an Ephermaral Ciphersuite");
        }
    }

     /**
     * Creates an extended TLS workflow including an application data and
     * heartbeat messages
     *
     * @return
     */
    public WorkflowTrace createFullWorkflow() {
        ConnectionEnd ourConnectionEnd = getSafeSingleContextConnectionEnd();

        WorkflowTrace workflowTrace = this.createHandshakeWorkflow(ourConnectionEnd);
        List<ProtocolMessage> messages = new LinkedList<>();
        if (config.isServerSendsApplicationData()) {
            messages.add(new ApplicationMessage(config));
            workflowTrace.addTlsAction(MessageActionFactory.createAction(ourConnectionEnd, ConnectionEndType.SERVER,
                    messages));
            messages = new LinkedList<>();
        }
        messages.add(new ApplicationMessage(config));

        if (config.isAddHeartbeatExtension()) {
            messages.add(new HeartbeatMessage(config));
            workflowTrace.addTlsAction(MessageActionFactory.createAction(ourConnectionEnd, ConnectionEndType.CLIENT,
                    messages));
            messages = new LinkedList<>();
            messages.add(new HeartbeatMessage(config));
            workflowTrace.addTlsAction(MessageActionFactory.createAction(ourConnectionEnd, ConnectionEndType.SERVER,
                    messages));
        } else {
            workflowTrace.addTlsAction(MessageActionFactory.createAction(ourConnectionEnd, ConnectionEndType.CLIENT,
                    messages));
        }
        return workflowTrace;
    }

    private WorkflowTrace createShortHelloWorkflow() {
        ConnectionEnd ourConnectionEnd = getSafeSingleContextConnectionEnd();
        WorkflowTrace trace = new WorkflowTrace(config);
        trace.addTlsAction(MessageActionFactory.createAction(ourConnectionEnd, ConnectionEndType.CLIENT,
                new ClientHelloMessage(config)));
        trace.addTlsAction(MessageActionFactory.createAction(ourConnectionEnd, ConnectionEndType.SERVER,
                new ServerHelloMessage(config)));
        return trace;
    }

    private WorkflowTrace createSsl2HelloWorkflow() {
        ConnectionEnd ourConnectionEnd = getSafeSingleContextConnectionEnd();
        WorkflowTrace trace = new WorkflowTrace(config);
        MessageAction action = MessageActionFactory.createAction(ourConnectionEnd, ConnectionEndType.CLIENT,
                new SSL2ClientHelloMessage(config));
        action.setRecords(new BlobRecord());
        trace.addTlsAction(action);
        action = MessageActionFactory.createAction(ourConnectionEnd, ConnectionEndType.SERVER,
                new SSL2ServerHelloMessage(config));
        action.setRecords(new BlobRecord());
        trace.addTlsAction(action);
        return trace;
    }

    private WorkflowTrace createFullResumptionWorkflow() {
        ConnectionEnd conEnd = getSafeSingleContextConnectionEnd();
        WorkflowTrace trace = this.createHandshakeWorkflow(conEnd);

        trace.addTlsAction(new ResetConnectionAction());
        WorkflowTrace tempTrace = this.createResumptionWorkflow();
        for (TLSAction resumption : tempTrace.getTlsActions()) {
            trace.addTlsAction(resumption);
        }
        return trace;
    }

    private WorkflowTrace createResumptionWorkflow() {
        ConnectionEnd ourConnectionEnd = getSafeSingleContextConnectionEnd();
        WorkflowTrace trace = new WorkflowTrace(config);
        MessageAction action = MessageActionFactory.createAction(ourConnectionEnd, ConnectionEndType.CLIENT,
                new ClientHelloMessage(config));
        trace.addTlsAction(action);
        action = MessageActionFactory.createAction(ourConnectionEnd, ConnectionEndType.SERVER, new ServerHelloMessage(
                config), new ChangeCipherSpecMessage(config), new FinishedMessage(config));
        trace.addTlsAction(action);
        action = MessageActionFactory.createAction(ourConnectionEnd, ConnectionEndType.CLIENT,
                new ChangeCipherSpecMessage(config), new FinishedMessage(config));
        trace.addTlsAction(action);

        return trace;
    }

    private WorkflowTrace createClientRenegotiationWorkflow() {
        ConnectionEnd conEnd = getSafeSingleContextConnectionEnd();
        WorkflowTrace trace = createHandshakeWorkflow(conEnd);
        trace.addTlsAction(new RenegotiationAction());
        WorkflowTrace renegotiationTrace = createHandshakeWorkflow(conEnd);
        for (TLSAction reneAction : renegotiationTrace.getTlsActions()) {
            trace.addTlsAction(reneAction);
        }
        return trace;
    }

    private WorkflowTrace createServerRenegotiationWorkflow() {
        ConnectionEnd ourConnectionEnd = getSafeSingleContextConnectionEnd();
        WorkflowTrace trace = createHandshakeWorkflow(ourConnectionEnd);
        WorkflowTrace renegotiationTrace = createHandshakeWorkflow(ourConnectionEnd);
        trace.addTlsAction(new RenegotiationAction());
        MessageAction action = MessageActionFactory.createAction(ourConnectionEnd, ConnectionEndType.SERVER,
                new HelloRequestMessage(config));
        trace.addTlsAction(action);
        for (TLSAction reneAction : renegotiationTrace.getTlsActions()) {
            trace.addTlsAction(reneAction);
        }
        return trace;
    }

    private WorkflowTrace createHttpsWorkflow() {
        ConnectionEnd ourConnectionEnd = getSafeSingleContextConnectionEnd();
        WorkflowTrace trace = createHandshakeWorkflow(ourConnectionEnd);
        MessageAction action = MessageActionFactory.createAction(ourConnectionEnd, ConnectionEndType.CLIENT,
                new HttpsRequestMessage(config));
        trace.addTlsAction(action);
        action = MessageActionFactory.createAction(ourConnectionEnd, ConnectionEndType.SERVER,
                new HttpsResponseMessage(config));
        trace.addTlsAction(action);
        return trace;
    }
}
