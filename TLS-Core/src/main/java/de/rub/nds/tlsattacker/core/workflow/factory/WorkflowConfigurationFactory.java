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
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.HttpsResponseMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EndOfEarlyDataMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskDhClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskDheServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskEcDhClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskEcDheServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskRsaClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SrpClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SrpServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EarlyDataExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ForwardAction;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.MessageActionFactory;
import de.rub.nds.tlsattacker.core.workflow.action.PrintLastHandledApplicationDataAction;
import de.rub.nds.tlsattacker.core.workflow.action.RenegotiationAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Create a WorkflowTace based on a Config instance.
 */
public class WorkflowConfigurationFactory {

    static final Logger LOGGER = LogManager.getLogger(WorkflowConfigurationFactory.class);

    protected final Config config;
    RunningModeType mode;

    public WorkflowConfigurationFactory(Config config) {
        this.config = config;
    }

    public WorkflowTrace createWorkflowTrace(WorkflowTraceType type, RunningModeType mode) {
        this.mode = mode;
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
            case CLIENT_RENEGOTIATION_WITHOUT_RESUMPTION:
                return createClientRenegotiationWorkflow();
            case CLIENT_RENEGOTIATION:
                return createClientRenegotiationWithResumptionWorkflow();
            case SERVER_RENEGOTIATION:
                return createServerRenegotiationWorkflow();
            case HTTPS:
                return createHttpsWorkflow();
            case RESUMPTION:
                return createResumptionWorkflow();
            case FULL_RESUMPTION:
                return createFullResumptionWorkflow();
            case SIMPLE_MITM_PROXY:
                return createSimpleMitmProxyWorkflow();
            case ZERO_RTT:
                return createZeroRttWorkflow();
            case FULL_ZERO_RTT:
                return createFullZeroRttWorkflow();
            case FALSE_START:
                return createFalseStartWorkflow();
        }
        throw new ConfigurationException("Unknown WorkflowTraceType " + type.name());
    }

    private AliasedConnection getConnection() {
        AliasedConnection con = null;
        if (null == mode) {
            throw new ConfigurationException("Running mode not set, can't configure workflow");
        } else {
            switch (mode) {
                case CLIENT:
                    con = config.getDefaultClientConnection();
                    break;
                case SERVER:
                    con = config.getDefaultServerConnection();
                    break;
                default:
                    throw new ConfigurationException("This workflow can only be configured for"
                            + " modes CLIENT and SERVER, but actual mode was " + mode);
            }
        }
        return con;
    }

    /**
     * Create a hello workflow for the default connection end defined in config.
     *
     * @return A HelloWorkflow
     */
    private WorkflowTrace createHelloWorkflow() {
        return createHelloWorkflow(getConnection());
    }

    /**
     * Create a hello workflow for the given connection end.
     */
    private WorkflowTrace createHelloWorkflow(AliasedConnection connection) {
        WorkflowTrace workflowTrace = new WorkflowTrace();

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

        workflowTrace.addTlsAction(MessageActionFactory.createAction(connection, ConnectionEndType.CLIENT, messages));
        if (config.getHighestProtocolVersion() == ProtocolVersion.DTLS10
                || config.getHighestProtocolVersion() == ProtocolVersion.DTLS12) {

            HelloVerifyRequestMessage helloVerifyRequestMessage = new HelloVerifyRequestMessage(config);
            helloVerifyRequestMessage.setIncludeInDigest(false);
            messages = new LinkedList<>();

            messages.add(helloVerifyRequestMessage);
            workflowTrace.addTlsAction(MessageActionFactory
                    .createAction(connection, ConnectionEndType.SERVER, messages));
            clientHello = new ClientHelloMessage(config);
            messages = new LinkedList<>();
            messages.add(clientHello);
            workflowTrace.addTlsAction(MessageActionFactory
                    .createAction(connection, ConnectionEndType.CLIENT, messages));
        }
        messages = new LinkedList<>();
        messages.add(new ServerHelloMessage(config));

        if (config.getHighestProtocolVersion().isTLS13()) {
            if (config.getTls13BackwardsCompatibilityMode() == Boolean.TRUE) {
                messages.add(new ChangeCipherSpecMessage());
            }
            messages.add(new EncryptedExtensionsMessage(config));
            if (config.isClientAuthentication()) {
                CertificateRequestMessage certRequest = new CertificateRequestMessage(config);
                messages.add(certRequest);
            }
            if (connection.getLocalConnectionEndType() == ConnectionEndType.CLIENT) {
                messages.add(new CertificateMessage());
            } else {
                messages.add(new CertificateMessage(config));
            }
            messages.add(new CertificateVerifyMessage(config));
            messages.add(new FinishedMessage(config));
        } else {
            if (!config.getDefaultSelectedCipherSuite().isSrpSha()
                    && !config.getDefaultSelectedCipherSuite().isPskOrDhPsk()) {
                if (connection.getLocalConnectionEndType() == ConnectionEndType.CLIENT) {
                    messages.add(new CertificateMessage());
                } else {
                    messages.add(new CertificateMessage(config));
                }
            }

            if (config.getDefaultSelectedCipherSuite().isEphemeral() || config.getDefaultSelectedCipherSuite().isSrp()) {
                addServerKeyExchangeMessage(messages);
            }

            if (config.isClientAuthentication()) {
                CertificateRequestMessage certRequest = new CertificateRequestMessage(config);
                messages.add(certRequest);
            }
            messages.add(new ServerHelloDoneMessage(config));
        }
        workflowTrace.addTlsAction(MessageActionFactory.createAction(connection, ConnectionEndType.SERVER, messages));

        return workflowTrace;
    }

    /**
     * Create a handshake workflow for the default connection end defined in
     * config.
     *
     * @return A HandshakeWorkflow
     */
    private WorkflowTrace createHandshakeWorkflow() {
        return createHandshakeWorkflow(getConnection());
    }

    /**
     * Create a handshake workflow for the given connection end.
     */
    private WorkflowTrace createHandshakeWorkflow(AliasedConnection connection) {

        WorkflowTrace workflowTrace = this.createHelloWorkflow(connection);
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
        workflowTrace.addTlsAction(MessageActionFactory.createAction(connection, ConnectionEndType.CLIENT, messages));
        if (!config.getHighestProtocolVersion().isTLS13()) {
            messages = new LinkedList<>();
            messages.add(new ChangeCipherSpecMessage(config));
            messages.add(new FinishedMessage(config));

            workflowTrace.addTlsAction(MessageActionFactory
                    .createAction(connection, ConnectionEndType.SERVER, messages));
        }

        return workflowTrace;
    }

    /**
     * Creates an extended TLS workflow including an application data and
     * heartbeat messages
     *
     * @return A FullWorkflow with ApplicationMessages
     */
    private WorkflowTrace createFullWorkflow() {
        AliasedConnection connection = getConnection();

        WorkflowTrace workflowTrace = this.createHandshakeWorkflow(connection);
        List<ProtocolMessage> messages = new LinkedList<>();
        if (config.isServerSendsApplicationData()) {
            messages.add(new ApplicationMessage(config));
            workflowTrace.addTlsAction(MessageActionFactory
                    .createAction(connection, ConnectionEndType.SERVER, messages));
            messages = new LinkedList<>();
        }
        messages.add(new ApplicationMessage(config));

        if (config.isAddHeartbeatExtension()) {
            messages.add(new HeartbeatMessage(config));
            workflowTrace.addTlsAction(MessageActionFactory
                    .createAction(connection, ConnectionEndType.CLIENT, messages));
            messages = new LinkedList<>();
            messages.add(new HeartbeatMessage(config));
            workflowTrace.addTlsAction(MessageActionFactory
                    .createAction(connection, ConnectionEndType.SERVER, messages));
        } else {
            workflowTrace.addTlsAction(MessageActionFactory
                    .createAction(connection, ConnectionEndType.CLIENT, messages));
        }
        return workflowTrace;
    }

    private WorkflowTrace createShortHelloWorkflow() {
        AliasedConnection connection = getConnection();
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(MessageActionFactory.createAction(connection, ConnectionEndType.CLIENT,
                new ClientHelloMessage(config)));
        trace.addTlsAction(MessageActionFactory.createAction(connection, ConnectionEndType.SERVER,
                new ServerHelloMessage(config)));
        return trace;
    }

    /**
     * Create a handshake workflow for the default connection end defined in
     * config.
     */
    private WorkflowTrace createFalseStartWorkflow() {
        return createFalseStartWorkflow(getConnection());
    }

    /**
     * Create a false start workflow for the given connection end.
     */
    private WorkflowTrace createFalseStartWorkflow(AliasedConnection connection) {

        if (config.getHighestProtocolVersion().isTLS13()) {
            throw new ConfigurationException("The false start workflow is not implemented for TLS 1.3");
        }

        WorkflowTrace workflowTrace = this.createHandshakeWorkflow(connection);
        MessageAction appData = MessageActionFactory.createAction(connection, ConnectionEndType.CLIENT,
                new ApplicationMessage(config));

        // Client CKE, CCS, Fin
        TlsAction lastClientAction;
        if (connection.getLocalConnectionEndType() == ConnectionEndType.CLIENT) {
            lastClientAction = (TlsAction) workflowTrace.getLastSendingAction();
        } else {
            lastClientAction = (TlsAction) workflowTrace.getLastReceivingAction();
        }
        int i = workflowTrace.getTlsActions().indexOf(lastClientAction);
        workflowTrace.addTlsAction(i + 1, appData);

        return workflowTrace;
    }

    private WorkflowTrace createSsl2HelloWorkflow() {
        AliasedConnection connection = getConnection();
        WorkflowTrace trace = new WorkflowTrace();
        MessageAction action = MessageActionFactory.createAction(connection, ConnectionEndType.CLIENT,
                new SSL2ClientHelloMessage(config));
        action.setRecords(new BlobRecord());
        trace.addTlsAction(action);
        action = MessageActionFactory.createAction(connection, ConnectionEndType.SERVER, new SSL2ServerHelloMessage(
                config));
        action.setRecords(new BlobRecord());
        trace.addTlsAction(action);
        return trace;
    }

    private WorkflowTrace createFullResumptionWorkflow() {
        AliasedConnection conEnd = getConnection();
        WorkflowTrace trace = this.createHandshakeWorkflow(conEnd);

        trace.addTlsAction(new ResetConnectionAction());
        WorkflowTrace tempTrace = this.createResumptionWorkflow();
        for (TlsAction resumption : tempTrace.getTlsActions()) {
            trace.addTlsAction(resumption);
        }
        return trace;
    }

    private WorkflowTrace createResumptionWorkflow() {
        AliasedConnection connection = getConnection();
        WorkflowTrace trace = new WorkflowTrace();
        MessageAction action = MessageActionFactory.createAction(connection, ConnectionEndType.CLIENT,
                new ClientHelloMessage(config));
        trace.addTlsAction(action);
        action = MessageActionFactory.createAction(connection, ConnectionEndType.SERVER,
                new ServerHelloMessage(config), new ChangeCipherSpecMessage(config), new FinishedMessage(config));
        trace.addTlsAction(action);
        action = MessageActionFactory.createAction(connection, ConnectionEndType.CLIENT, new ChangeCipherSpecMessage(
                config), new FinishedMessage(config));
        trace.addTlsAction(action);

        return trace;
    }

    private WorkflowTrace createClientRenegotiationWithResumptionWorkflow() {
        AliasedConnection conEnd = getConnection();
        WorkflowTrace trace = createHandshakeWorkflow(conEnd);
        trace.addTlsAction(new RenegotiationAction());
        WorkflowTrace renegotiationTrace = createResumptionWorkflow();
        for (TlsAction reneAction : renegotiationTrace.getTlsActions()) {
            trace.addTlsAction(reneAction);
        }
        return trace;
    }

    private WorkflowTrace createClientRenegotiationWorkflow() {
        AliasedConnection conEnd = getConnection();
        WorkflowTrace trace = createHandshakeWorkflow(conEnd);
        trace.addTlsAction(new RenegotiationAction());
        WorkflowTrace renegotiationTrace = createHandshakeWorkflow(conEnd);
        for (TlsAction reneAction : renegotiationTrace.getTlsActions()) {
            trace.addTlsAction(reneAction);
        }
        return trace;
    }

    private WorkflowTrace createServerRenegotiationWorkflow() {
        AliasedConnection connection = getConnection();
        WorkflowTrace trace = createHandshakeWorkflow(connection);
        WorkflowTrace renegotiationTrace = createHandshakeWorkflow(connection);
        trace.addTlsAction(new RenegotiationAction());
        MessageAction action = MessageActionFactory.createAction(connection, ConnectionEndType.SERVER,
                new HelloRequestMessage(config));
        trace.addTlsAction(action);
        for (TlsAction reneAction : renegotiationTrace.getTlsActions()) {
            trace.addTlsAction(reneAction);
        }
        return trace;
    }

    private WorkflowTrace createHttpsWorkflow() {
        AliasedConnection connection = getConnection();
        WorkflowTrace trace = createHandshakeWorkflow(connection);
        MessageAction action = MessageActionFactory.createAction(connection, ConnectionEndType.CLIENT,
                new HttpsRequestMessage(config));
        trace.addTlsAction(action);
        action = MessageActionFactory.createAction(connection, ConnectionEndType.SERVER, new HttpsResponseMessage(
                config));
        trace.addTlsAction(action);
        return trace;
    }

    private WorkflowTrace createSimpleMitmProxyWorkflow() {

        if (mode != RunningModeType.MITM) {
            throw new ConfigurationException("This workflow trace can only be created when running"
                    + " in MITM mode. Actual mode: " + mode);
        }

        AliasedConnection inboundConnection = config.getDefaultServerConnection();
        AliasedConnection outboundConnection = config.getDefaultClientConnection();

        if (outboundConnection == null || inboundConnection == null) {
            throw new ConfigurationException("Could not find both necesary connection ends");
        }

        // client -> mitm
        String clientToMitmAlias = inboundConnection.getAlias();
        // mitm -> server
        String mitmToServerAlias = outboundConnection.getAlias();

        LOGGER.debug("Building mitm trace for: " + inboundConnection + ", " + outboundConnection);

        WorkflowTrace clientToMitmHandshake = createHandshakeWorkflow(inboundConnection);
        WorkflowTrace mitmToServerHandshake = createHandshakeWorkflow(outboundConnection);

        WorkflowTrace trace = new WorkflowTrace();
        trace.addConnection(inboundConnection);
        trace.addConnection(outboundConnection);
        trace.addTlsActions(clientToMitmHandshake.getTlsActions());
        trace.addTlsActions(mitmToServerHandshake.getTlsActions());

        // Forward request client -> server
        ForwardAction f = new ForwardAction(clientToMitmAlias, mitmToServerAlias, new ApplicationMessage(config));
        trace.addTlsAction(f);

        // Print the application data contents to console
        PrintLastHandledApplicationDataAction p = new PrintLastHandledApplicationDataAction(clientToMitmAlias);
        p.setStringEncoding("US_ASCII");
        trace.addTlsAction(p);

        // // Forward response server -> client
        // List<ProtocolMessage> messages = new LinkedList<>();
        // f = new ForwardAction(mitmToServerAlias, clientToMitmAlias, new
        // ApplicationMessage(config));
        // trace.addTlsAction(f);
        //
        // // Print the server's answer
        // p = new PrintLastHandledApplicationDataAction(mitmToServerAlias);
        // p.setStringEncoding(StandardCharsets.US_ASCII);
        // trace.addTlsAction(p);
        return trace;
    }

    private WorkflowTrace createZeroRttWorkflow() {
        AliasedConnection connection = getConnection();
        WorkflowTrace trace = new WorkflowTrace();

        List<ProtocolMessage> clientHelloMessages = new LinkedList<>();
        List<ProtocolMessage> serverMessages = new LinkedList<>();
        List<ProtocolMessage> clientMessages = new LinkedList<>();

        ClientHelloMessage clientHello;
        ApplicationMessage earlyDataMsg;

        if (connection.getLocalConnectionEndType() == ConnectionEndType.CLIENT) {
            clientHello = new ClientHelloMessage(config);
            earlyDataMsg = new ApplicationMessage(config);
            earlyDataMsg.setDataConfig(config.getEarlyData());
        } else {
            clientHello = new ClientHelloMessage();
            earlyDataMsg = new ApplicationMessage();
        }
        clientHelloMessages.add(clientHello);
        clientHelloMessages.add(earlyDataMsg);

        trace.addTlsAction(MessageActionFactory.createAction(connection, ConnectionEndType.CLIENT, clientHelloMessages));

        ServerHelloMessage serverHello;
        EncryptedExtensionsMessage encExtMsg;
        FinishedMessage serverFin = new FinishedMessage(config);

        if (connection.getLocalConnectionEndType() == ConnectionEndType.CLIENT) {
            serverHello = new ServerHelloMessage();
            encExtMsg = new EncryptedExtensionsMessage();
            encExtMsg.addExtension(new EarlyDataExtensionMessage());
        } else {
            serverHello = new ServerHelloMessage(config);
            encExtMsg = new EncryptedExtensionsMessage(config);
            encExtMsg.addExtension(new EarlyDataExtensionMessage());
        }

        serverMessages.add(serverHello);
        serverMessages.add(encExtMsg);
        serverMessages.add(serverFin);

        trace.addTlsAction(MessageActionFactory.createAction(connection, ConnectionEndType.SERVER, serverMessages));

        clientMessages.add(new EndOfEarlyDataMessage());
        clientMessages.add(new FinishedMessage(config));
        clientMessages.add(new ApplicationMessage(config));
        trace.addTlsAction(MessageActionFactory.createAction(connection, ConnectionEndType.CLIENT, clientMessages));
        return trace;
    }

    private WorkflowTrace createFullZeroRttWorkflow() {
        AliasedConnection ourConnection = getConnection();
        WorkflowTrace trace = createHandshakeWorkflow();
        // Remove extensions that are only required in the 2nd ClientHello
        for (TlsAction action : trace.getTlsActions()) {
            if (action.isMessageAction()) {
                for (ProtocolMessage msg : ((MessageAction) action).getMessages()) {
                    if (msg instanceof ClientHelloMessage) {
                        List<ExtensionMessage> extensions = ((ClientHelloMessage) msg).getExtensions();
                        for (int x = 0; x < extensions.size(); x++) {
                            if (extensions.get(x) instanceof PreSharedKeyExtensionMessage
                                    || extensions.get(x) instanceof EarlyDataExtensionMessage) {
                                ((ClientHelloMessage) msg).getExtensions().remove(extensions.get(x));
                                x--;
                            }
                        }
                    }
                }
            }
        }
        trace.addTlsAction(MessageActionFactory.createAction(ourConnection, ConnectionEndType.SERVER,
                new NewSessionTicketMessage(false)));
        trace.addTlsAction(new ResetConnectionAction());
        WorkflowTrace zeroRttTrace = createZeroRttWorkflow();
        for (TlsAction zeroRttAction : zeroRttTrace.getTlsActions()) {
            trace.addTlsAction(zeroRttAction);
        }
        return trace;
    }

    public ClientKeyExchangeMessage createClientKeyExchangeMessage(KeyExchangeAlgorithm algorithm) {
        if (algorithm != null) {
            switch (algorithm) {
                case RSA:
                    return new RSAClientKeyExchangeMessage(config);
                case ECDHE_ECDSA:
                case ECDH_ECDSA:
                case ECDH_RSA:
                case ECDHE_RSA:
                    return new ECDHClientKeyExchangeMessage(config);
                case DHE_DSS:
                case DHE_RSA:
                case DH_ANON:
                case DH_DSS:
                case DH_RSA:
                    return new DHClientKeyExchangeMessage(config);
                case PSK:
                    return new PskClientKeyExchangeMessage(config);
                case DHE_PSK:
                    return new PskDhClientKeyExchangeMessage(config);
                case ECDHE_PSK:
                    return new PskEcDhClientKeyExchangeMessage(config);
                case RSA_PSK:
                    return new PskRsaClientKeyExchangeMessage(config);
                case SRP_SHA_DSS:
                case SRP_SHA_RSA:
                case SRP_SHA:
                    return new SrpClientKeyExchangeMessage(config);
                default:
                    LOGGER.warn("Unsupported key exchange algorithm: " + algorithm
                            + ", not creating ClientKeyExchange Message");

            }
        } else {
            LOGGER.warn("Unsupported key exchange algorithm: " + algorithm + ", not creating ClientKeyExchange Message");
        }
        return null;
    }

    private void addClientKeyExchangeMessage(List<ProtocolMessage> messages) {
        CipherSuite cs = config.getDefaultSelectedCipherSuite();
        ClientKeyExchangeMessage message = createClientKeyExchangeMessage(AlgorithmResolver.getKeyExchangeAlgorithm(cs));
        messages.add(message);
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
                case PSK:
                    messages.add(new PskServerKeyExchangeMessage(config));
                    break;
                case DHE_PSK:
                    messages.add(new PskDheServerKeyExchangeMessage(config));
                    break;
                case ECDHE_PSK:
                    messages.add(new PskEcDheServerKeyExchangeMessage(config));
                    break;
                case SRP_SHA_DSS:
                case SRP_SHA_RSA:
                case SRP_SHA:
                    messages.add(new SrpServerKeyExchangeMessage(config));
                    break;
                default:
                    LOGGER.warn("Unsupported key exchange algorithm: " + AlgorithmResolver.getKeyExchangeAlgorithm(cs)
                            + ", not adding ServerKeyExchange Message");
                    break;
            }
        }
        if (cs.isSrp()) {
            messages.add(new SrpServerKeyExchangeMessage(config));
        }
    }
}
