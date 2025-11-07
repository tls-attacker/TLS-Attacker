/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.factory;

import de.rub.nds.protocol.exception.ConfigurationException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.http.HttpRequestMessage;
import de.rub.nds.tlsattacker.core.http.HttpResponseMessage;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.pop3.command.*;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3InitialGreeting;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3STLSReply;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AckMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EndOfEarlyDataMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.GOSTClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PWDClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PWDServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskDhClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskDheServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskEcDhClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskEcDheServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskRsaClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SrpClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SrpServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CookieExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EarlyDataExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.quic.constants.QuicTransportErrorCodes;
import de.rub.nds.tlsattacker.core.quic.frame.AckFrame;
import de.rub.nds.tlsattacker.core.quic.frame.ConnectionCloseFrame;
import de.rub.nds.tlsattacker.core.quic.frame.HandshakeDoneFrame;
import de.rub.nds.tlsattacker.core.quic.frame.PingFrame;
import de.rub.nds.tlsattacker.core.quic.packet.RetryPacket;
import de.rub.nds.tlsattacker.core.quic.packet.VersionNegotiationPacket;
import de.rub.nds.tlsattacker.core.smtp.command.*;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpInitialGreeting;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpSTARTTLSReply;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.action.*;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Create a WorkflowTrace based on a Config instance. */
public class WorkflowConfigurationFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final Config config;
    private RunningModeType mode;

    public WorkflowConfigurationFactory(Config config) {
        this.config = config;
    }

    public WorkflowTrace createWorkflowTrace(WorkflowTraceType type, RunningModeType mode) {
        this.mode = mode;
        if (type == null) {
            throw new RuntimeException("Cannot create WorkflowTrace from NULL type");
        }
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
            case DYNAMIC_CLIENT_RENEGOTIATION_WITHOUT_RESUMPTION:
                return createDynamicClientRenegotiationWithoutResumption();
            case HTTPS:
                return createHttpsWorkflow();
            case POP3:
                return createPop3Workflow();
            case POP3_STARTTLS:
                return createPop3StarttlsWorkflow();
            case SMTP:
                return createSmtpWorkflow();
            case SMTP_STARTTLS:
                return createSmtpStarttlsWorkflow();
            case RESUMPTION:
                return createResumptionWorkflow();
            case FULL_RESUMPTION:
                return createFullResumptionWorkflow();
            case SIMPLE_MITM_PROXY:
                return createSimpleMitmProxyWorkflow();
            case SIMPLE_FORWARDING_MITM_PROXY:
                return createSimpleForwardingMitmProxyWorkflow();
            case TLS13_PSK:
                return createTls13PskWorkflow(false);
            case FULL_TLS13_PSK:
                return createFullTls13PskWorkflow(false);
            case ZERO_RTT:
                return createTls13PskWorkflow(true);
            case FULL_ZERO_RTT:
                return createFullTls13PskWorkflow(true);
            case FALSE_START:
                return createFalseStartWorkflow();
            case RSA_SYNC_PROXY:
                return createSyncProxyWorkflow();
            case DYNAMIC_HANDSHAKE:
                return createDynamicHandshakeWorkflow();
            case DYNAMIC_HELLO:
                return createDynamicHelloWorkflow();
            case DYNAMIC_HTTPS:
                return createHttpsDynamicWorkflow();
            case QUIC_VERSION_NEGOTIATION:
                return createQuicVersionNegotiationWorkflow();
            case QUIC_PORT_CONNECTION_MIGRATION:
                return createQuicConnectionMigrationWorkflow(false);
            case QUIC_IPV6_CONNECTION_MIGRATION:
                return createQuicConnectionMigrationWorkflow(true);
            default:
                throw new ConfigurationException("Unknown WorkflowTraceType " + type.name());
        }
    }

    private AliasedConnection getConnection() {
        AliasedConnection con = null;
        if (mode == null) {
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
                    throw new ConfigurationException(
                            "This workflow can only be configured for"
                                    + " modes CLIENT and SERVER, but actual mode was "
                                    + mode);
            }
        }
        return con;
    }

    /**
     * Create an empty - or almost empty workflow trace, depending on the StartTLS flag in the
     * config.
     *
     * @param connection
     * @return An entry workflow trace
     */
    public WorkflowTrace createTlsEntryWorkflowTrace(AliasedConnection connection) {
        WorkflowTrace workflowTrace = new WorkflowTrace();

        if (config.getStarttlsType() != StarttlsType.NONE) {
            addStartTlsActions(connection, config.getStarttlsType(), workflowTrace);
        }

        if (config.getQuicRetryFlowRequired()) {
            workflowTrace.addTlsAction(
                    MessageActionFactory.createTLSAction(
                            config,
                            connection,
                            ConnectionEndType.CLIENT,
                            new ClientHelloMessage(config)));
            workflowTrace.addTlsAction(
                    MessageActionFactory.createQuicAction(
                            config, connection, ConnectionEndType.SERVER, new RetryPacket()));
        }

        return workflowTrace;
    }

    /**
     * Create a short hello workflow for the default connection end defined in config.
     *
     * @return A short hello workflow
     */
    private WorkflowTrace createShortHelloWorkflow() {
        return createShortHelloWorkflow(getConnection());
    }

    /**
     * Create a short hello workflow for the given connection end.
     *
     * @param connection
     * @return A short hello workflow
     */
    public WorkflowTrace createShortHelloWorkflow(AliasedConnection connection) {
        WorkflowTrace workflowTrace = createTlsEntryWorkflowTrace(connection);

        if (config.isAddEncryptedServerNameIndicationExtension()
                && connection.getLocalConnectionEndType() == ConnectionEndType.CLIENT) {
            workflowTrace.addTlsAction(new EsniKeyDnsRequestAction());
        }
        if (config.isAddEncryptedClientHelloExtension()
                && connection.getLocalConnectionEndType() == ConnectionEndType.CLIENT) {
            workflowTrace.addTlsAction(new EchConfigDnsRequestAction());
        }

        workflowTrace.addTlsAction(
                MessageActionFactory.createTLSAction(
                        config,
                        connection,
                        ConnectionEndType.CLIENT,
                        generateClientHelloMessage(config, connection)));

        if (config.getHighestProtocolVersion().isDTLS() && config.isDtlsCookieExchange()) {
            if (config.getHighestProtocolVersion().isDTLS13()) {
                ServerHelloMessage serverHelloMessage = new ServerHelloMessage(config, true);
                serverHelloMessage.addExtension(new CookieExtensionMessage());
                workflowTrace.addTlsAction(
                        MessageActionFactory.createTLSAction(
                                config, connection, ConnectionEndType.SERVER, serverHelloMessage));
            } else {
                workflowTrace.addTlsAction(
                        MessageActionFactory.createTLSAction(
                                config,
                                connection,
                                ConnectionEndType.SERVER,
                                new HelloVerifyRequestMessage()));
            }

            CoreClientHelloMessage clientHello = generateClientHelloMessage(config, connection);
            // Add extension that are required
            if (config.getHighestProtocolVersion().isDTLS13()
                    && config.isDtlsCookieExchange()
                    && !clientHello.getExtensions().contains(CookieExtensionMessage.class)) {
                clientHello.addExtension(new CookieExtensionMessage());
            }
            workflowTrace.addTlsAction(
                    MessageActionFactory.createTLSAction(
                            config, connection, ConnectionEndType.CLIENT, clientHello));
        }

        workflowTrace.addTlsAction(
                MessageActionFactory.createTLSAction(
                        config,
                        connection,
                        ConnectionEndType.SERVER,
                        new ServerHelloMessage(config)));

        return workflowTrace;
    }

    /**
     * Create a hello workflow for the default connection end defined in config.
     *
     * @return A hello workflow
     */
    private WorkflowTrace createHelloWorkflow() {
        return createHelloWorkflow(getConnection());
    }

    /**
     * Create a hello workflow for the given connection end.
     *
     * @param connection
     * @return A hello workflow
     */
    public WorkflowTrace createHelloWorkflow(AliasedConnection connection) {
        WorkflowTrace trace = createShortHelloWorkflow(connection);
        trace.removeTlsAction(trace.getTlsActions().size() - 1);

        CipherSuite selectedCipherSuite = config.getDefaultSelectedCipherSuite();
        List<ProtocolMessage> messages = new LinkedList<>();
        messages.add(new ServerHelloMessage(config));
        if (config.getHighestProtocolVersion().isTLS13()) {
            if (Objects.equals(config.getTls13BackwardsCompatibilityMode(), Boolean.TRUE)
                    || connection.getLocalConnectionEndType() == ConnectionEndType.CLIENT) {
                ChangeCipherSpecMessage ccs = new ChangeCipherSpecMessage();
                ccs.setRequired(false);
                messages.add(ccs);
            }
        }
        if (config.getHighestProtocolVersion().is13()) {
            messages.add(new EncryptedExtensionsMessage(config));
            if (Objects.equals(config.isClientAuthentication(), Boolean.TRUE)) {
                messages.add(new CertificateRequestMessage(config));
            }
            if (!selectedCipherSuite.isPWD()) {
                messages.add(new CertificateMessage());
                messages.add(new CertificateVerifyMessage());
            }
            messages.add(new FinishedMessage());
        } else {
            if (selectedCipherSuite.requiresServerCertificateMessage()) {
                messages.add(new CertificateMessage());
            }
            addServerKeyExchangeMessage(messages);
            if (Objects.equals(config.isClientAuthentication(), Boolean.TRUE)) {
                messages.add(new CertificateRequestMessage(config));
            }
            messages.add(new ServerHelloDoneMessage());
        }
        trace.addTlsAction(
                MessageActionFactory.createTLSAction(
                        config, connection, ConnectionEndType.SERVER, messages));

        return trace;
    }

    /**
     * Create a handshake workflow for the default connection end defined in config.
     *
     * @return A handshake workflow
     */
    private WorkflowTrace createHandshakeWorkflow() {
        return createHandshakeWorkflow(getConnection());
    }

    /**
     * Create a handshake workflow for the given connection end.
     *
     * @param connection
     * @return A handshake workflow
     */
    public WorkflowTrace createHandshakeWorkflow(AliasedConnection connection) {
        WorkflowTrace workflowTrace = createHelloWorkflow(connection);

        List<ProtocolMessage> messages = new LinkedList<>();
        if (config.getHighestProtocolVersion().isTLS13()) {
            if (Objects.equals(config.getTls13BackwardsCompatibilityMode(), Boolean.TRUE)
                    || connection.getLocalConnectionEndType() == ConnectionEndType.SERVER) {
                ChangeCipherSpecMessage ccs = new ChangeCipherSpecMessage();
                ccs.setRequired(false);
                messages.add(ccs);
            }
        }
        if (config.getHighestProtocolVersion().is13()) {
            if (config.isClientAuthentication()) {
                messages.add(new CertificateMessage());
                messages.add(new CertificateVerifyMessage());
            }
        } else {
            if (config.isClientAuthentication()) {
                messages.add(new CertificateMessage());
                addClientKeyExchangeMessage(messages);
                messages.add(new CertificateVerifyMessage());
            } else {
                addClientKeyExchangeMessage(messages);
            }
            messages.add(new ChangeCipherSpecMessage());
        }
        messages.add(new FinishedMessage());
        workflowTrace.addTlsAction(
                MessageActionFactory.createTLSAction(
                        config, connection, ConnectionEndType.CLIENT, messages));
        if (!config.getHighestProtocolVersion().is13()) {
            workflowTrace.addTlsAction(
                    MessageActionFactory.createTLSAction(
                            config,
                            connection,
                            ConnectionEndType.SERVER,
                            new ChangeCipherSpecMessage(),
                            new FinishedMessage()));
        }
        if (config.getHighestProtocolVersion().isDTLS13()) {
            workflowTrace.addTlsAction(
                    MessageActionFactory.createTLSAction(
                            config, connection, ConnectionEndType.SERVER, new AckMessage()));
        }
        if (config.getExpectHandshakeDoneQuicFrame()) {
            workflowTrace.addTlsAction(new ReceiveQuicTillAction(new HandshakeDoneFrame()));
        }
        return workflowTrace;
    }

    /**
     * Create a full workflow for the default connection end defined in config.
     *
     * @return A full workflow
     */
    private WorkflowTrace createFullWorkflow() {
        return createFullWorkflow(getConnection());
    }

    /**
     * Create an extended TLS workflow including an application data and heartbeat messages.
     *
     * @param connection
     * @return A full workflow with application messages
     */
    public WorkflowTrace createFullWorkflow(AliasedConnection connection) {
        WorkflowTrace trace = createHandshakeWorkflow(connection);

        if (config.isServerSendsApplicationData()) {
            trace.addTlsAction(
                    MessageActionFactory.createTLSAction(
                            config,
                            connection,
                            ConnectionEndType.SERVER,
                            new ApplicationMessage()));
        }

        if (config.isAddHeartbeatExtension()) {
            trace.addTlsAction(
                    MessageActionFactory.createTLSAction(
                            config,
                            connection,
                            ConnectionEndType.CLIENT,
                            new ApplicationMessage(),
                            new HeartbeatMessage()));
            trace.addTlsAction(
                    MessageActionFactory.createTLSAction(
                            config, connection, ConnectionEndType.SERVER, new HeartbeatMessage()));
        } else {
            trace.addTlsAction(
                    MessageActionFactory.createTLSAction(
                            config,
                            connection,
                            ConnectionEndType.CLIENT,
                            new ApplicationMessage()));
        }

        return trace;
    }

    /** Create a handshake workflow for the default connection end defined in config. */
    private WorkflowTrace createFalseStartWorkflow() {
        return createFalseStartWorkflow(getConnection());
    }

    /** Create a false start workflow for the given connection end. */
    private WorkflowTrace createFalseStartWorkflow(AliasedConnection connection) {

        if (config.getHighestProtocolVersion().is13()) {
            throw new ConfigurationException(
                    "The false start workflow is not implemented for (D)TLS 1.3");
        }

        WorkflowTrace workflowTrace = this.createHandshakeWorkflow(connection);
        MessageAction appData =
                MessageActionFactory.createTLSAction(
                        config, connection, ConnectionEndType.CLIENT, new ApplicationMessage());

        // Client CKE, CCS, Fin
        // Find the last action by the client (either our last send if we're the client,
        // or our last receive if we're the server receiving from the client)
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
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace =
                factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());

        MessageAction action =
                MessageActionFactory.createSSL2Action(
                        config, connection, ConnectionEndType.CLIENT, new SSL2ClientHelloMessage());
        trace.addTlsAction(action);
        action =
                MessageActionFactory.createSSL2Action(
                        config, connection, ConnectionEndType.SERVER, new SSL2ServerHelloMessage());
        trace.addTlsAction(action);
        return trace;
    }

    private WorkflowTrace createFullResumptionWorkflow() {
        AliasedConnection conEnd = getConnection();
        WorkflowTrace trace = this.createHandshakeWorkflow(conEnd);
        if (config.getHighestProtocolVersion().isDTLS() && config.isFinishWithCloseNotify()) {
            AlertMessage alert = new AlertMessage();
            alert.setConfig(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);
            trace.addTlsAction(new SendAction(alert));
        }
        trace.addTlsAction(new ResetConnectionAction());
        WorkflowTrace tempTrace = this.createResumptionWorkflow();
        for (TlsAction resumption : tempTrace.getTlsActions()) {
            trace.addTlsAction(resumption);
        }
        return trace;
    }

    /**
     * Create a resumption workflow for the default connection end defined in config. This can be
     * used as the follow up to a normal handshake to test session resumption capabilities.
     *
     * @return A resumption workflow
     */
    private WorkflowTrace createResumptionWorkflow() {
        return createResumptionWorkflow(getConnection());
    }

    /**
     * Create a resumption workflow for the given connection end. This can be used as the follow up
     * to a normal handshake to test session resumption capabilities.
     *
     * @param connection
     * @return A resumption workflow
     */
    public WorkflowTrace createResumptionWorkflow(AliasedConnection connection) {
        WorkflowTrace trace = createTlsEntryWorkflowTrace(connection);

        trace.addTlsAction(
                MessageActionFactory.createTLSAction(
                        config,
                        connection,
                        ConnectionEndType.CLIENT,
                        generateClientHelloMessage(config, connection)));

        if (config.getHighestProtocolVersion().isDTLS() && config.isDtlsCookieExchange()) {
            trace.addTlsAction(
                    MessageActionFactory.createTLSAction(
                            config,
                            connection,
                            ConnectionEndType.SERVER,
                            new HelloVerifyRequestMessage()));
            trace.addTlsAction(
                    MessageActionFactory.createTLSAction(
                            config,
                            connection,
                            ConnectionEndType.CLIENT,
                            generateClientHelloMessage(config, connection)));
        }

        trace.addTlsAction(
                MessageActionFactory.createTLSAction(
                        config,
                        connection,
                        ConnectionEndType.SERVER,
                        new ServerHelloMessage(config),
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()));
        trace.addTlsAction(
                MessageActionFactory.createTLSAction(
                        config,
                        connection,
                        ConnectionEndType.CLIENT,
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()));

        return trace;
    }

    private WorkflowTrace createClientRenegotiationWithResumptionWorkflow() {
        AliasedConnection conEnd = getConnection();
        WorkflowTrace trace = createHandshakeWorkflow(conEnd);
        trace.addTlsAction(new RenegotiationAction());
        WorkflowTrace renegotiationTrace = createResumptionWorkflow();
        for (TlsAction reneAction : renegotiationTrace.getTlsActions()) {
            if (reneAction.isMessageAction()) { // DO NOT ADD ASCII ACTIONS
                trace.addTlsAction(reneAction);
            }
        }
        return trace;
    }

    private WorkflowTrace createClientRenegotiationWorkflow() {
        AliasedConnection conEnd = getConnection();
        WorkflowTrace trace = createHandshakeWorkflow(conEnd);
        trace.addTlsAction(new RenegotiationAction());
        trace.addTlsAction(new FlushSessionCacheAction());
        WorkflowTrace renegotiationTrace = createHandshakeWorkflow(conEnd);
        for (TlsAction reneAction : renegotiationTrace.getTlsActions()) {
            if (reneAction.isMessageAction()) { // DO NOT ADD ASCII ACTIONS
                trace.addTlsAction(reneAction);
            }
        }
        return trace;
    }

    private WorkflowTrace createServerRenegotiationWorkflow() {
        AliasedConnection connection = getConnection();
        WorkflowTrace trace = createHandshakeWorkflow(connection);
        WorkflowTrace renegotiationTrace = createHandshakeWorkflow(connection);
        trace.addTlsAction(new RenegotiationAction());
        MessageAction action =
                MessageActionFactory.createTLSAction(
                        config, connection, ConnectionEndType.SERVER, new HelloRequestMessage());
        trace.addTlsAction(action);
        for (TlsAction reneAction : renegotiationTrace.getTlsActions()) {
            if (reneAction.isMessageAction()) { // DO NOT ADD ASCII ACTIONS
                trace.addTlsAction(reneAction);
            }
        }
        return trace;
    }

    private WorkflowTrace createHttpsWorkflow() {
        AliasedConnection connection = getConnection();
        WorkflowTrace trace = createHandshakeWorkflow(connection);
        appendHttpMessages(connection, trace);
        return trace;
    }

    private WorkflowTrace createPop3Workflow() {
        AliasedConnection connection = getConnection();
        WorkflowTrace trace = new WorkflowTrace();

        if (connection.getLocalConnectionEndType() == ConnectionEndType.CLIENT) {
            trace.addTlsAction(
                    MessageActionFactory.createPop3Action(
                            config,
                            connection,
                            ConnectionEndType.SERVER,
                            new Pop3InitialGreeting()));

            appendPop3CommandAndReplyActions(connection, trace, new Pop3USERCommand());
            appendPop3CommandAndReplyActions(connection, trace, new Pop3PASSCommand());
            appendPop3CommandAndReplyActions(connection, trace, new Pop3NOOPCommand());
            appendPop3CommandAndReplyActions(connection, trace, new Pop3STATCommand());
            appendPop3CommandAndReplyActions(connection, trace, new Pop3LISTCommand());
            appendPop3CommandAndReplyActions(connection, trace, new Pop3LISTCommand(1));
            appendPop3CommandAndReplyActions(connection, trace, new Pop3RETRCommand(1));
            appendPop3CommandAndReplyActions(connection, trace, new Pop3DELECommand(1));
            appendPop3CommandAndReplyActions(connection, trace, new Pop3QUITCommand());
        }

        return trace;
    }

    private WorkflowTrace createPop3StarttlsWorkflow() {
        AliasedConnection connection = getConnection();
        WorkflowTrace trace = createDynamicHandshakeWorkflow(connection);
        // kind of dirty changing it from the back, but otherwise we have to rework the whole
        // dynamic handshake mechanism
        trace.addTlsAction(0, new SendAction(new Pop3STLSCommand()));
        trace.addTlsAction(1, new ReceiveAction(new Pop3STLSReply()));
        // POP3 layer stack has disabled RECORD+MESSAGE per default
        trace.addTlsAction(2, new EnableLayerAction(ImplementedLayers.RECORD, ImplementedLayers.MESSAGE));

        List<TlsAction> pop3Actions = createPop3Workflow().getTlsActions();
        trace.addTlsAction(0, pop3Actions.get(0));
        for (int i = 1; i < pop3Actions.size(); i++) {
            trace.addTlsAction(pop3Actions.get(i));
        }

        return trace;
    }

    private WorkflowTrace createSmtpWorkflow() {
        AliasedConnection connection = getConnection();
        WorkflowTrace trace = new WorkflowTrace();
        if (connection.getLocalConnectionEndType() == ConnectionEndType.CLIENT) {
            trace.addTlsAction(
                    MessageActionFactory.createSmtpAction(
                            config,
                            connection,
                            ConnectionEndType.SERVER,
                            new SmtpInitialGreeting()));
        }
        appendSmtpCommandAndReplyActions(connection, trace, new SmtpEHLOCommand());
        appendSmtpCommandAndReplyActions(connection, trace, new SmtpAUTHCommand());
        appendSmtpCommandAndReplyActions(connection, trace, new SmtpAUTHCredentialsCommand());
        appendSmtpCommandAndReplyActions(connection, trace, new SmtpNOOPCommand());
        appendSmtpCommandAndReplyActions(connection, trace, new SmtpMAILCommand());
        appendSmtpCommandAndReplyActions(connection, trace, new SmtpRCPTCommand());
        appendSmtpCommandAndReplyActions(connection, trace, new SmtpDATACommand());
        appendSmtpCommandAndReplyActions(connection, trace, new SmtpDATAContentCommand("Test"));
        appendSmtpCommandAndReplyActions(connection, trace, new SmtpQUITCommand());

        return trace;
    }

    private WorkflowTrace createSmtpStarttlsWorkflow() {
        AliasedConnection connection = getConnection();
        WorkflowTrace trace = createDynamicHandshakeWorkflow(connection);
        // kind of dirty changing it from the back, but otherwise we have to rework the whole
        // dynamic handshake mechanism
        trace.addTlsAction(0, new SendAction(new SmtpSTARTTLSCommand()));
        trace.addTlsAction(1, new ReceiveAction(new SmtpSTARTTLSReply()));
        // SMTP layer stack has disabled RECORD+MESSAGE per default
        trace.addTlsAction(2, new EnableLayerAction(ImplementedLayers.RECORD, ImplementedLayers.MESSAGE));

        // put InitialGreeting back to the front
        List<TlsAction> smtpActions = createSmtpWorkflow().getTlsActions();
        trace.addTlsAction(0, smtpActions.get(0));
        for (int i = 1; i < smtpActions.size(); i++) {
            trace.addTlsAction(smtpActions.get(i));
        }

        return trace;
    }

    private void appendPop3CommandAndReplyActions(
            AliasedConnection connection, WorkflowTrace trace, Pop3Command command) {
        MessageAction clientAction =
                MessageActionFactory.createPop3Action(
                        config, connection, ConnectionEndType.CLIENT, command);
        trace.addTlsAction(clientAction);
        MessageAction serverAction =
                MessageActionFactory.createPop3Action(
                        config,
                        connection,
                        ConnectionEndType.SERVER,
                        command.getCommandType().createReply());
        trace.addTlsAction(serverAction);
    }

    private void appendSmtpCommandAndReplyActions(
            AliasedConnection connection, WorkflowTrace trace, SmtpCommand command) {
        MessageAction clientAction =
                MessageActionFactory.createSmtpAction(
                        config, connection, ConnectionEndType.CLIENT, command);
        trace.addTlsAction(clientAction);
        MessageAction serverAction =
                MessageActionFactory.createSmtpAction(
                        config,
                        connection,
                        ConnectionEndType.SERVER,
                        command.getCommandType().createReply());
        trace.addTlsAction(serverAction);
    }

    private WorkflowTrace createHttpsDynamicWorkflow() {
        AliasedConnection connection = getConnection();
        WorkflowTrace trace = createDynamicHandshakeWorkflow();

        appendHttpMessages(connection, trace);
        return trace;
    }

    public void appendHttpMessages(AliasedConnection connection, WorkflowTrace trace) {
        MessageAction action =
                MessageActionFactory.createHttpAction(
                        config,
                        connection,
                        ConnectionEndType.CLIENT,
                        new HttpRequestMessage(config));
        trace.addTlsAction(action);
        action =
                MessageActionFactory.createHttpAction(
                        config, connection, ConnectionEndType.SERVER, new HttpResponseMessage());
        trace.addTlsAction(action);
    }

    private WorkflowTrace createSimpleMitmProxyWorkflow() {

        if (mode != RunningModeType.MITM) {
            throw new ConfigurationException(
                    "This workflow trace can only be created when running"
                            + " in MITM mode. Actual mode: "
                            + mode);
        }

        AliasedConnection inboundConnection = config.getDefaultServerConnection();
        AliasedConnection outboundConnection = config.getDefaultClientConnection();

        if (outboundConnection == null || inboundConnection == null) {
            throw new ConfigurationException("Could not find both necessary connection ends");
        }

        // client -> mitm
        String clientToMitmAlias = inboundConnection.getAlias();
        // mitm -> server
        String mitmToServerAlias = outboundConnection.getAlias();

        LOGGER.debug("Building mitm trace for: {}, {}", inboundConnection, outboundConnection);

        WorkflowTrace clientToMitmHandshake = createHandshakeWorkflow(inboundConnection);
        WorkflowTrace mitmToServerHandshake = createHandshakeWorkflow(outboundConnection);

        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace worklfowTrace =
                factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());

        worklfowTrace.addConnection(inboundConnection);
        worklfowTrace.addConnection(outboundConnection);
        worklfowTrace.addTlsActions(clientToMitmHandshake.getTlsActions());
        worklfowTrace.addTlsActions(mitmToServerHandshake.getTlsActions());

        // Forward request client -> server
        ForwardMessagesAction f =
                new ForwardMessagesAction(
                        clientToMitmAlias, mitmToServerAlias, new ApplicationMessage());
        worklfowTrace.addTlsAction(f);

        // Print client's app data contents
        PrintLastHandledApplicationDataAction p =
                new PrintLastHandledApplicationDataAction(clientToMitmAlias);
        p.setStringEncoding("US-ASCII");
        worklfowTrace.addTlsAction(p);

        // Forward response server -> client
        f =
                new ForwardMessagesAction(
                        mitmToServerAlias, clientToMitmAlias, new ApplicationMessage());
        worklfowTrace.addTlsAction(f);

        // Print server's app data contents
        p = new PrintLastHandledApplicationDataAction(mitmToServerAlias);
        p.setStringEncoding("US-ASCII");
        worklfowTrace.addTlsAction(p);

        return worklfowTrace;
    }

    private WorkflowTrace createSimpleForwardingMitmProxyWorkflow() {

        if (mode != RunningModeType.MITM) {
            throw new ConfigurationException(
                    "This workflow trace can only be created when running"
                            + " in MITM mode. Actual mode: "
                            + mode);
        }

        AliasedConnection inboundConnection = config.getDefaultServerConnection();
        AliasedConnection outboundConnection = config.getDefaultClientConnection();

        if (outboundConnection == null || inboundConnection == null) {
            throw new ConfigurationException("Could not find both necessary connection ends");
        }

        // client -> mitm
        String clientToMitmAlias = inboundConnection.getAlias();
        // mitm -> server
        String mitmToServerAlias = outboundConnection.getAlias();

        LOGGER.debug("Building mitm trace for: {}, {}", inboundConnection, outboundConnection);

        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace =
                factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());

        trace.addConnection(inboundConnection);
        trace.addConnection(outboundConnection);

        // <!-- CH-->
        ForwardRecordsAction forwardRecordsAction =
                new ForwardRecordsAction(clientToMitmAlias, mitmToServerAlias);
        trace.addTlsAction(forwardRecordsAction);

        // <!-- SH, Cert, SHD-->
        ForwardRecordsAction forwardRecordsAction2 =
                new ForwardRecordsAction(mitmToServerAlias, clientToMitmAlias);
        trace.addTlsAction(forwardRecordsAction2);

        // <!-- CKE, CCS, Fin -->
        ForwardRecordsAction forwardRecordsAction3 =
                new ForwardRecordsAction(clientToMitmAlias, mitmToServerAlias);
        trace.addTlsAction(forwardRecordsAction3);

        // <!-- CCS, Fin -->
        ForwardRecordsAction forwardRecordsAction4 =
                new ForwardRecordsAction(mitmToServerAlias, clientToMitmAlias);
        trace.addTlsAction(forwardRecordsAction4);
        return trace;
    }

    private WorkflowTrace createTls13PskWorkflow(boolean zeroRtt) {
        AliasedConnection connection = getConnection();
        ChangeCipherSpecMessage ccsServer = new ChangeCipherSpecMessage();
        ChangeCipherSpecMessage ccsClient = new ChangeCipherSpecMessage();

        if (connection.getLocalConnectionEndType() == ConnectionEndType.CLIENT) {
            ccsServer.setRequired(false);
        } else {
            ccsClient.setRequired(false);
        }

        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace =
                factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());

        List<ProtocolMessage> clientHelloMessages = new LinkedList<>();
        List<ProtocolMessage> serverMessages = new LinkedList<>();
        List<ProtocolMessage> clientMessages = new LinkedList<>();

        CoreClientHelloMessage clientHello;
        ApplicationMessage earlyDataMsg;
        FinishedMessage serverFin = new FinishedMessage();

        if (connection.getLocalConnectionEndType() == ConnectionEndType.CLIENT) {
            clientHello = generateClientHelloMessage(config, connection);
            earlyDataMsg = new ApplicationMessage();
            earlyDataMsg.setDataConfig(config.getEarlyData());
        } else {
            clientHello = generateClientHelloMessage(config, connection);
            earlyDataMsg = new ApplicationMessage();
        }
        clientHelloMessages.add(clientHello);
        if (zeroRtt) {
            if ((Objects.equals(config.getTls13BackwardsCompatibilityMode(), Boolean.TRUE)
                            || connection.getLocalConnectionEndType() == ConnectionEndType.SERVER)
                    && !config.getHighestProtocolVersion().isDTLS13()) {
                clientHelloMessages.add(ccsClient);
            }
            clientHelloMessages.add(earlyDataMsg);
        }

        trace.addTlsAction(
                MessageActionFactory.createTLSAction(
                        config, connection, ConnectionEndType.CLIENT, clientHelloMessages));

        if (config.getHighestProtocolVersion().isDTLS() && config.isDtlsCookieExchange()) {
            ServerHelloMessage serverHelloMessage = new ServerHelloMessage(config, true);
            serverHelloMessage.addExtension(new CookieExtensionMessage());
            trace.addTlsAction(
                    MessageActionFactory.createTLSAction(
                            config, connection, ConnectionEndType.SERVER, serverHelloMessage));
            ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
            clientHelloMessage.addExtension(new CookieExtensionMessage());
            trace.addTlsAction(
                    MessageActionFactory.createTLSAction(
                            config, connection, ConnectionEndType.CLIENT, clientHelloMessage));
        }
        ServerHelloMessage serverHello = new ServerHelloMessage(config);
        serverMessages.add(serverHello);
        EncryptedExtensionsMessage encExtMsg = new EncryptedExtensionsMessage(config);
        if (zeroRtt) {
            encExtMsg.addExtension(new EarlyDataExtensionMessage());
        }
        if ((Objects.equals(config.getTls13BackwardsCompatibilityMode(), Boolean.TRUE)
                        || connection.getLocalConnectionEndType() == ConnectionEndType.CLIENT)
                && !config.getHighestProtocolVersion().isDTLS13()) {
            serverMessages.add(ccsServer);
        }
        if (!zeroRtt
                && (Objects.equals(config.getTls13BackwardsCompatibilityMode(), Boolean.TRUE)
                        || connection.getLocalConnectionEndType() == ConnectionEndType.SERVER)
                && !config.getHighestProtocolVersion().isDTLS13()) {
            clientMessages.add(ccsClient);
        }
        serverMessages.add(encExtMsg);
        serverMessages.add(serverFin);

        MessageAction serverMsgsAction =
                MessageActionFactory.createTLSAction(
                        config, connection, ConnectionEndType.SERVER, serverMessages);
        serverMsgsAction.addActionOption(ActionOption.IGNORE_UNEXPECTED_NEW_SESSION_TICKETS);
        trace.addTlsAction(serverMsgsAction);

        // quic 0rtt does not use the EndOfEarlyDataMessage
        if (zeroRtt && !config.getQuic()) {
            clientMessages.add(new EndOfEarlyDataMessage());
        }
        clientMessages.add(new FinishedMessage());
        trace.addTlsAction(
                MessageActionFactory.createTLSAction(
                        config, connection, ConnectionEndType.CLIENT, clientMessages));

        if (config.getHighestProtocolVersion().isDTLS13()) {
            trace.addTlsAction(
                    MessageActionFactory.createTLSAction(
                            config, connection, ConnectionEndType.SERVER, new AckMessage()));
        }
        return trace;
    }

    private WorkflowTrace createFullTls13PskWorkflow(boolean zeroRtt) {
        AliasedConnection ourConnection = getConnection();
        WorkflowTrace trace = createHandshakeWorkflow();
        // Remove extensions that are only required in the second handshake
        if (ourConnection.getLocalConnectionEndType() == ConnectionEndType.CLIENT) {
            List<ProtocolMessage> clientHellos =
                    WorkflowTraceConfigurationUtil.getStaticConfiguredSendMessages(
                            trace, HandshakeMessageType.CLIENT_HELLO);
            for (ProtocolMessage handshakeMessage : clientHellos) {
                ClientHelloMessage clientHello = (ClientHelloMessage) handshakeMessage;
                if (clientHello.getExtensions() != null) {
                    EarlyDataExtensionMessage earlyDataExtension =
                            clientHello.getExtension(EarlyDataExtensionMessage.class);
                    clientHello.getExtensions().remove(earlyDataExtension);
                    PreSharedKeyExtensionMessage pskExtension =
                            clientHello.getExtension(PreSharedKeyExtensionMessage.class);
                    clientHello.getExtensions().remove(pskExtension);
                }
            }
        } else {
            ServerHelloMessage serverHello =
                    (ServerHelloMessage)
                            WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                    trace, HandshakeMessageType.SERVER_HELLO);
            if (serverHello.getExtensions() != null) {
                PreSharedKeyExtensionMessage pskExtension =
                        serverHello.getExtension(PreSharedKeyExtensionMessage.class);
                serverHello.getExtensions().remove(pskExtension);
            }
            EncryptedExtensionsMessage encryptedExtensionsMessage =
                    (EncryptedExtensionsMessage)
                            WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                    trace, HandshakeMessageType.ENCRYPTED_EXTENSIONS);
            if (encryptedExtensionsMessage != null
                    && encryptedExtensionsMessage.getExtensions() != null) {
                EarlyDataExtensionMessage earlyDataExtension =
                        encryptedExtensionsMessage.getExtension(EarlyDataExtensionMessage.class);
                encryptedExtensionsMessage.getExtensions().remove(earlyDataExtension);
            }
        }

        MessageAction newSessionTicketAction =
                MessageActionFactory.createTLSAction(
                        config,
                        ourConnection,
                        ConnectionEndType.SERVER,
                        new NewSessionTicketMessage(config, false));
        if (newSessionTicketAction instanceof ReceiveAction) {
            newSessionTicketAction
                    .getActionOptions()
                    .add(ActionOption.IGNORE_UNEXPECTED_NEW_SESSION_TICKETS);
        }
        trace.addTlsAction(newSessionTicketAction);
        if (config.getHighestProtocolVersion().isDTLS() && config.isFinishWithCloseNotify()) {
            AlertMessage alert = new AlertMessage();
            alert.setConfig(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);
            trace.addTlsAction(new SendAction(alert));
        }
        if (config.getQuic()) {
            trace.addTlsAction(
                    MessageActionFactory.createQuicAction(
                            config,
                            ourConnection,
                            ConnectionEndType.CLIENT,
                            new ConnectionCloseFrame(QuicTransportErrorCodes.NO_ERROR.getValue())));
        }
        trace.addTlsAction(new ResetConnectionAction());
        WorkflowTrace zeroRttTrace = createTls13PskWorkflow(zeroRtt);
        for (TlsAction zeroRttAction : zeroRttTrace.getTlsActions()) {
            trace.addTlsAction(zeroRttAction);
        }
        return trace;
    }

    /**
     * A simple synchronizing proxy for RSA KE.
     *
     * <p>Synchronizes the secrets between all parties and forwards first round of exchanged
     * application data messages.
     *
     * <p>Works only for RSA KE ciphers. Extended Master Secret (and possibly other extensions) will
     * brake it. So per default, all extensions are removed and all cipher suites except RSA suites
     * are removed, too.
     */
    private WorkflowTrace createSyncProxyWorkflow() {

        if (mode != RunningModeType.MITM) {
            throw new ConfigurationException(
                    "This workflow trace can only be created when running"
                            + " in MITM mode. Actual mode: "
                            + mode);
        }

        // client -> mitm
        AliasedConnection inboundConnection = config.getDefaultServerConnection();
        String clientToMitmAlias = inboundConnection.getAlias();
        // mitm -> server
        AliasedConnection outboundConnection = config.getDefaultClientConnection();
        String mitmToServerAlias = outboundConnection.getAlias();

        if (outboundConnection == null || inboundConnection == null) {
            throw new ConfigurationException("Could not find both necessary connection ends");
        }

        LOGGER.info(
                "Building synchronizing proxy trace for:\n{}, {}",
                inboundConnection.toCompactString(),
                outboundConnection.toCompactString());

        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace =
                factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());

        trace.addConnection(inboundConnection);
        trace.addConnection(outboundConnection);

        List<CipherSuite> removeCiphers = CipherSuite.getImplemented();
        removeCiphers.addAll(CipherSuite.getNotImplemented());
        List<CipherSuite> keepCiphers = new ArrayList<>();
        for (CipherSuite cs : removeCiphers) {
            if (cs.name().startsWith("TLS_RSA")) {
                keepCiphers.add(cs);
            }
        }
        removeCiphers.removeAll(keepCiphers);

        List<ExtensionType> removeExtensions = ExtensionType.getReceivable();
        List<ExtensionType> keepExtensions = new ArrayList<>();
        // keepExtensions.add(ExtensionType.EXTENDED_MASTER_SECRET);
        removeExtensions.removeAll(keepExtensions);

        // Sorry for fooling the silly formatter with EOL comments :>
        trace.addTlsActions( // Forward CH, remove extensions and non RSA KE ciphers
                new BufferedGenericReceiveAction(clientToMitmAlias), //
                new CopyBuffersAction(clientToMitmAlias, mitmToServerAlias), //
                new RemBufferedChCiphersAction(mitmToServerAlias, removeCiphers), //
                new RemBufferedChExtensionsAction(mitmToServerAlias, removeExtensions), //
                new BufferedSendAction(mitmToServerAlias), //
                new ClearBuffersAction(clientToMitmAlias), //

                // Forward SH
                new BufferedGenericReceiveAction(mitmToServerAlias),
                new CopyBuffersAction(mitmToServerAlias, clientToMitmAlias),
                new PopAndSendAction(clientToMitmAlias), //
                new PrintSecretsAction(clientToMitmAlias), //
                new PrintSecretsAction(mitmToServerAlias), //
                // But send our own certificate
                new PopBufferedMessageAction(clientToMitmAlias), //
                new PopBufferedRecordAction(clientToMitmAlias), //
                new SendAction(clientToMitmAlias, new CertificateMessage()), //
                // Send SHD
                new PopAndSendAction(clientToMitmAlias), //
                new ClearBuffersAction(mitmToServerAlias), //

                // Forward CKE (use received PMS)
                new BufferedGenericReceiveAction(clientToMitmAlias), //
                new CopyBuffersAction(clientToMitmAlias, mitmToServerAlias), //
                new PopBuffersAction(mitmToServerAlias), //
                new CopyPreMasterSecretAction(clientToMitmAlias, mitmToServerAlias), //
                new SendAction(mitmToServerAlias, new RSAClientKeyExchangeMessage()), //
                // Sends CCS
                new PopAndSendAction(mitmToServerAlias), //
                new ClearBuffersAction(mitmToServerAlias), //
                new ClearBuffersAction(clientToMitmAlias), //

                // Send fresh FIN
                new SendAction(mitmToServerAlias, new FinishedMessage()), //
                new PrintSecretsAction(clientToMitmAlias), //
                new PrintSecretsAction(mitmToServerAlias), //

                // Finish the handshake, and print the secrets we negotiated
                new ReceiveAction(
                        mitmToServerAlias,
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()), //
                new PrintSecretsAction(clientToMitmAlias), //
                new PrintSecretsAction(mitmToServerAlias), //
                new SendAction(
                        clientToMitmAlias,
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()), //

                // Step out, enjoy :)
                new ForwardDataAction(clientToMitmAlias, mitmToServerAlias), //
                new ForwardDataAction(mitmToServerAlias, clientToMitmAlias)); //

        return trace;
    }

    public ClientKeyExchangeMessage createClientKeyExchangeMessage(KeyExchangeAlgorithm algorithm) {
        if (algorithm != null) {
            switch (algorithm) {
                case RSA:
                case RSA_EXPORT:
                    return new RSAClientKeyExchangeMessage();
                case ECDHE_ECDSA:
                case ECDH_ECDSA:
                case ECDH_RSA:
                case ECDHE_RSA:
                case ECDH_ANON:
                    return new ECDHClientKeyExchangeMessage();
                case DHE_DSS:
                case DHE_RSA:
                case DH_ANON:
                case DH_DSS:
                case DH_RSA:
                    return new DHClientKeyExchangeMessage();
                case PSK:
                    return new PskClientKeyExchangeMessage();
                case DHE_PSK:
                    return new PskDhClientKeyExchangeMessage();
                case ECDHE_PSK:
                    return new PskEcDhClientKeyExchangeMessage();
                case RSA_PSK:
                    return new PskRsaClientKeyExchangeMessage();
                case SRP_SHA_DSS:
                case SRP_SHA_RSA:
                case SRP_SHA:
                    return new SrpClientKeyExchangeMessage();
                case VKO_GOST01:
                case VKO_GOST12:
                    return new GOSTClientKeyExchangeMessage();
                case ECCPWD:
                    return new PWDClientKeyExchangeMessage();
                default:
                    LOGGER.warn(
                            "Unsupported key exchange algorithm: '{}', not creating ClientKeyExchange Message",
                            algorithm);
            }
        } else {
            LOGGER.warn(
                    "Unsupported key exchange algorithm: 'null', not creating ClientKeyExchange Message");
        }
        return null;
    }

    public ServerKeyExchangeMessage createServerKeyExchangeMessage(KeyExchangeAlgorithm algorithm) {
        if (algorithm != null) {
            switch (algorithm) {
                case RSA:
                case DH_DSS:
                case DH_RSA:
                    return null;
                case ECDHE_ECDSA:
                case ECDHE_RSA:
                case ECDH_ANON:
                    return new ECDHEServerKeyExchangeMessage();
                case DHE_DSS:
                case DHE_RSA:
                case DH_ANON:
                    return new DHEServerKeyExchangeMessage();
                case PSK:
                    return new PskServerKeyExchangeMessage();
                case DHE_PSK:
                    return new PskDheServerKeyExchangeMessage();
                case ECDHE_PSK:
                    return new PskEcDheServerKeyExchangeMessage();
                case SRP_SHA_DSS:
                case SRP_SHA_RSA:
                case SRP_SHA:
                    return new SrpServerKeyExchangeMessage();
                case ECCPWD:
                    return new PWDServerKeyExchangeMessage();
                case RSA_EXPORT:
                    // TODO We are always adding the server rsa cke message, even though it should
                    // only be added when our certificate public key is too big.
                    return new RSAServerKeyExchangeMessage();

                default:
                    LOGGER.warn(
                            "Unsupported key exchange algorithm: '{}', not creating ServerKeyExchange Message",
                            algorithm);
            }
        } else {
            LOGGER.warn(
                    "Unsupported key exchange algorithm: 'null', not creating ServerKeyExchange Message");
        }

        return null;
    }

    public void addClientKeyExchangeMessage(List<ProtocolMessage> messages) {
        CipherSuite cs = config.getDefaultSelectedCipherSuite();
        ClientKeyExchangeMessage message =
                createClientKeyExchangeMessage(cs.getKeyExchangeAlgorithm());
        if (message != null) {
            messages.add(message);
        }
    }

    public void addServerKeyExchangeMessage(List<ProtocolMessage> messages) {
        CipherSuite cs = config.getDefaultSelectedCipherSuite();
        ServerKeyExchangeMessage message =
                createServerKeyExchangeMessage(cs.getKeyExchangeAlgorithm());
        if (message != null) {
            messages.add(message);
        }
    }

    public WorkflowTrace addStartTlsActions(
            AliasedConnection connection, StarttlsType type, WorkflowTrace workflowTrace) {
        // TODO: fix for the new layer system since we removed ascii actions, leaving the old code
        // for when this is
        /*
         * switch (type) { case FTP: { workflowTrace.addTlsAction(MessageActionFactory.createAsciiAction(connection,
         * ConnectionEndType.SERVER, StarttlsMessage.FTP_S_CONNECTED.getStarttlsMessage(), "US-ASCII"));
         * workflowTrace.addTlsAction(MessageActionFactory.createAsciiAction(connection, ConnectionEndType.CLIENT,
         * StarttlsMessage.FTP_TLS.getStarttlsMessage(), "US-ASCII"));
         * workflowTrace.addTlsAction(MessageActionFactory.createAsciiAction(connection, ConnectionEndType.SERVER,
         * StarttlsMessage.FTP_S_READY.getStarttlsMessage(), "US-ASCII")); return workflowTrace; } case IMAP: {
         * workflowTrace.addTlsAction(MessageActionFactory.createAsciiAction(connection, ConnectionEndType.SERVER,
         * StarttlsMessage.IMAP_S_CONNECTED.getStarttlsMessage(), "US-ASCII"));
         * workflowTrace.addTlsAction(MessageActionFactory.createAsciiAction(connection, ConnectionEndType.CLIENT,
         * StarttlsMessage.IMAP_TLS.getStarttlsMessage(), "US-ASCII"));
         * workflowTrace.addTlsAction(MessageActionFactory.createAsciiAction(connection, ConnectionEndType.SERVER,
         * StarttlsMessage.IMAP_S_READY.getStarttlsMessage(), "US-ASCII")); return workflowTrace; } case POP3: {
         * workflowTrace.addTlsAction(MessageActionFactory.createAsciiAction(connection, ConnectionEndType.SERVER,
         * StarttlsMessage.POP3_S_CONNECTED.getStarttlsMessage(), "US-ASCII"));
         * workflowTrace.addTlsAction(MessageActionFactory.createAsciiAction(connection, ConnectionEndType.CLIENT,
         * StarttlsMessage.POP3_TLS.getStarttlsMessage(), "US-ASCII"));
         * workflowTrace.addTlsAction(MessageActionFactory.createAsciiAction(connection, ConnectionEndType.SERVER,
         * StarttlsMessage.POP3_S_READY.getStarttlsMessage(), "US-ASCII")); return workflowTrace; } case SMTP: {
         * workflowTrace.addTlsAction(MessageActionFactory.createAsciiAction(connection, ConnectionEndType.SERVER,
         * StarttlsMessage.SMTP_S_CONNECTED.getStarttlsMessage(), "US-ASCII"));
         * workflowTrace.addTlsAction(MessageActionFactory.createAsciiAction(connection, ConnectionEndType.CLIENT,
         * StarttlsMessage.SMTP_C_CONNECTED.getStarttlsMessage(), "US-ASCII"));
         * workflowTrace.addTlsAction(MessageActionFactory.createAsciiAction(connection, ConnectionEndType.SERVER,
         * StarttlsMessage.SMTP_S_OK.getStarttlsMessage(), "US-ASCII"));
         * workflowTrace.addTlsAction(MessageActionFactory.createAsciiAction(connection, ConnectionEndType.CLIENT,
         * StarttlsMessage.SMTP_TLS.getStarttlsMessage(), "US-ASCII"));
         * workflowTrace.addTlsAction(MessageActionFactory.createAsciiAction(connection, ConnectionEndType.SERVER,
         * StarttlsMessage.SMTP_S_READY.getStarttlsMessage(), "US-ASCII")); return workflowTrace; } default: return
         * workflowTrace;
         */
        return null;
    }

    /**
     * Create a dynamic hello workflow for the default connection end defined in config.
     *
     * @return A dynamic hello workflow
     */
    private WorkflowTrace createDynamicHelloWorkflow() {
        return createDynamicHelloWorkflow(getConnection());
    }

    /**
     * Create a dynamic hello workflow for the given connection end.
     *
     * @param connection
     * @return A dynamic hello workflow
     */
    public WorkflowTrace createDynamicHelloWorkflow(AliasedConnection connection) {
        WorkflowTrace trace = createTlsEntryWorkflowTrace(connection);

        if (config.isAddEncryptedServerNameIndicationExtension()
                && connection.getLocalConnectionEndType() == ConnectionEndType.CLIENT) {
            trace.addTlsAction(new EsniKeyDnsRequestAction());
        }
        if (config.isAddEncryptedClientHelloExtension()
                && connection.getLocalConnectionEndType() == ConnectionEndType.CLIENT) {
            trace.addTlsAction(new EchConfigDnsRequestAction());
        }

        trace.addTlsAction(
                MessageActionFactory.createTLSAction(
                        config,
                        connection,
                        ConnectionEndType.CLIENT,
                        generateClientHelloMessage(config, connection)));

        if ((config.getHighestProtocolVersion().isDTLS() && config.isDtlsCookieExchange())) {
            if (config.getHighestProtocolVersion().isDTLS13()) {
                ServerHelloMessage serverHelloMessage = new ServerHelloMessage(config, true);
                serverHelloMessage.addExtension(new CookieExtensionMessage());
                trace.addTlsAction(
                        MessageActionFactory.createTLSAction(
                                config, connection, ConnectionEndType.SERVER, serverHelloMessage));
            } else {
                trace.addTlsAction(
                        MessageActionFactory.createTLSAction(
                                config,
                                connection,
                                ConnectionEndType.SERVER,
                                new HelloVerifyRequestMessage()));
            }

            CoreClientHelloMessage clientHello = generateClientHelloMessage(config, connection);
            // Add extension that are required
            if (config.getHighestProtocolVersion().isDTLS13()
                    && config.isDtlsCookieExchange()
                    && !clientHello.getExtensions().contains(CookieExtensionMessage.class)) {
                clientHello.addExtension(new CookieExtensionMessage());
            }
            trace.addTlsAction(
                    MessageActionFactory.createTLSAction(
                            config, connection, ConnectionEndType.CLIENT, clientHello));
        }

        if (connection.getLocalConnectionEndType() == ConnectionEndType.CLIENT) {

            if (config.getHighestProtocolVersion().is13()) {
                trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
            } else {
                trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
            }
            return trace;
        } else {
            if (config.getHighestProtocolVersion().is13()) {
                List<ProtocolMessage> tls13Messages = new LinkedList<>();
                tls13Messages.add(new ServerHelloMessage(config));
                if (Objects.equals(config.getTls13BackwardsCompatibilityMode(), Boolean.TRUE)
                        && !config.getHighestProtocolVersion().isDTLS13()) {
                    ChangeCipherSpecMessage ccs = new ChangeCipherSpecMessage();
                    ccs.setRequired(false);
                    tls13Messages.add(ccs);
                }
                tls13Messages.add(new EncryptedExtensionsMessage(config));
                if (Objects.equals(config.isClientAuthentication(), Boolean.TRUE)) {
                    tls13Messages.add(new CertificateRequestMessage(config));
                }
                tls13Messages.add(new CertificateMessage());
                tls13Messages.add(new CertificateVerifyMessage());
                tls13Messages.add(new FinishedMessage());
                trace.addTlsAction(
                        MessageActionFactory.createTLSAction(
                                config, connection, ConnectionEndType.SERVER, tls13Messages));
            } else {
                trace.addTlsAction(new SendAction(new ServerHelloMessage(config)));
                trace.addTlsAction(new SendDynamicServerCertificateAction());
                trace.addTlsAction(new SendDynamicServerKeyExchangeAction());
                if (Objects.equals(config.isClientAuthentication(), Boolean.TRUE)) {
                    trace.addTlsAction(new SendAction(new CertificateRequestMessage(config)));
                }
                trace.addTlsAction(new SendAction(new ServerHelloDoneMessage()));
            }
            return trace;
        }
    }

    /**
     * Create a dynamic handshake workflow for the default connection end defined in config.
     *
     * @return A dynamic handshake workflow
     */
    private WorkflowTrace createDynamicHandshakeWorkflow() {
        return createDynamicHandshakeWorkflow(getConnection());
    }

    /**
     * Create a dynamic handshake workflow for the given connection end.
     *
     * @param connection
     * @return A dynamic handshake workflow
     */
    public WorkflowTrace createDynamicHandshakeWorkflow(AliasedConnection connection) {
        WorkflowTrace trace = createDynamicHelloWorkflow(connection);
        if (connection.getLocalConnectionEndType() == ConnectionEndType.CLIENT) {
            if (config.getHighestProtocolVersion().is13()) {
                List<ProtocolMessage> tls13Messages = new LinkedList<>();
                if (Objects.equals(config.getTls13BackwardsCompatibilityMode(), Boolean.TRUE)
                        && !config.getHighestProtocolVersion().isDTLS13()) {
                    ChangeCipherSpecMessage ccs = new ChangeCipherSpecMessage();
                    ccs.setRequired(false);
                    tls13Messages.add(ccs);
                }
                if (Objects.equals(config.isClientAuthentication(), Boolean.TRUE)) {
                    tls13Messages.add(new CertificateMessage());
                    tls13Messages.add(new CertificateVerifyMessage());
                }
                tls13Messages.add(new FinishedMessage());
                trace.addTlsAction(
                        MessageActionFactory.createTLSAction(
                                config, connection, ConnectionEndType.CLIENT, tls13Messages));
                if (config.getExpectHandshakeDoneQuicFrame()) {
                    trace.addTlsAction(new ReceiveQuicTillAction(new HandshakeDoneFrame()));
                }
                if (config.getHighestProtocolVersion().isDTLS13()) {
                    trace.addTlsAction(new ReceiveAction(new AckMessage()));
                }
            } else {

                if (Objects.equals(config.isClientAuthentication(), Boolean.TRUE)) {
                    trace.addTlsAction(new SendAction(new CertificateMessage()));
                    trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                    trace.addTlsAction(new SendAction(new CertificateVerifyMessage()));
                } else {
                    trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                }
                trace.addTlsAction(
                        new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
                trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
            }
            return trace;
        } else {
            trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));
            if (config.getHighestProtocolVersion().isDTLS13()) {
                trace.addTlsAction(new SendAction(new AckMessage()));
            } else {
                trace.addTlsAction(
                        new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
            }
            return trace;
        }
    }

    private WorkflowTrace createQuicVersionNegotiationWorkflow() {
        return createQuicVersionNegotiationWorkflow(getConnection());
    }

    public WorkflowTrace createQuicVersionNegotiationWorkflow(AliasedConnection connection) {
        WorkflowTrace trace = createTlsEntryWorkflowTrace(connection);
        trace.addTlsAction(
                MessageActionFactory.createTLSAction(
                        config,
                        connection,
                        ConnectionEndType.CLIENT,
                        new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new VersionNegotiationPacket()));
        return trace;
    }

    private WorkflowTrace createQuicConnectionMigrationWorkflow(boolean switchToIPv6) {
        return createQuicConnectionMigrationWorkflow(getConnection(), switchToIPv6);
    }

    public WorkflowTrace createQuicConnectionMigrationWorkflow(
            AliasedConnection connection, boolean switchToIPv6) {
        WorkflowTrace trace = createDynamicHandshakeWorkflow();
        trace.addTlsAction(new ResetConnectionAction(false, switchToIPv6));
        trace.addTlsAction(
                MessageActionFactory.createQuicAction(
                        config, connection, ConnectionEndType.CLIENT, new PingFrame()));
        TlsAction pathChallengeAction = new QuicPathChallengeAction(connection.getAlias(), false);
        trace.addTlsAction(pathChallengeAction);
        trace.addTlsAction(
                MessageActionFactory.createQuicAction(
                        config, connection, ConnectionEndType.CLIENT, new PingFrame()));
        trace.addTlsAction(
                MessageActionFactory.createQuicAction(
                        config, connection, ConnectionEndType.SERVER, new AckFrame(false)));
        return trace;
    }

    private WorkflowTrace createDynamicClientRenegotiationWithoutResumption() {
        WorkflowTrace trace = createDynamicHandshakeWorkflow();
        trace.addTlsAction(new RenegotiationAction());
        trace.addTlsAction(new FlushSessionCacheAction());
        WorkflowTrace renegotiationTrace = createDynamicHandshakeWorkflow();
        for (TlsAction reneAction : renegotiationTrace.getTlsActions()) {
            if (reneAction.isMessageAction()) { // DO NOT ADD ASCII ACTIONS
                trace.addTlsAction(reneAction);
            }
        }
        return trace;
    }

    private CoreClientHelloMessage generateClientHelloMessage(
            Config tlsConfig, AliasedConnection connection) {
        if (config.isAddEncryptedClientHelloExtension()
                && connection.getLocalConnectionEndType() == ConnectionEndType.CLIENT) {
            return new EncryptedClientHelloMessage(config);
        } else {
            return new ClientHelloMessage(config);
        }
    }
}
