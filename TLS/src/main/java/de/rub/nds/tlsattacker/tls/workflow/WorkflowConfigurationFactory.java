/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.tls.config.CommandConfig;
import de.rub.nds.tlsattacker.tls.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageTypeHolder;
import de.rub.nds.tlsattacker.tls.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.tls.constants.NameType;
import de.rub.nds.tlsattacker.tls.protocol.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.application.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.workflow.action.MessageActionFactory;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public abstract class WorkflowConfigurationFactory {

    static final Logger LOGGER = LogManager.getLogger(WorkflowConfigurationFactory.class);

    protected final CommandConfig config;

    public WorkflowConfigurationFactory(CommandConfig config) {
	this.config = config;
    }

    /**
     * This method constructs an instance of WorkflowConfigurationFactory based
     * on the used CommandConfig parameter. It can be either a dynamic
     * configuration factory or a static configuration factory, with a
     * predefined list of protocol messages.
     * 
     * The list of protocol messages is generated based on the first ciphersuite
     * in the ciphersuite list.
     * 
     * @param config
     * @return
     */
    public static WorkflowConfigurationFactory createInstance(CommandConfig config) {
	if (config.isDynamicWorkflow()) {
	    // TODO create a factory for dynamic workflow
	    throw new UnsupportedOperationException("This configuration is not " + "supported yet");
	} else {
	    // we decide based on the first cipher how to construct a handshake.
	    CipherSuite cs = config.getCipherSuites().get(0);
	    try {
		switch (AlgorithmResolver.getKeyExchangeAlgorithm(cs)) {
		    case RSA:
			if (config.getProtocolVersion() == ProtocolVersion.DTLS10
				|| config.getProtocolVersion() == ProtocolVersion.DTLS12) {
			    return new DtlsRsaWorkflowConfigurationFactory(config);
			} else {
			    return new RsaWorkflowConfigurationFactory(config);
			}
		    case EC_DIFFIE_HELLMAN:
			if (config.getProtocolVersion() == ProtocolVersion.DTLS10
				|| config.getProtocolVersion() == ProtocolVersion.DTLS12) {
			    return new DtlsEcdhWorkflowConfigurationFactory(config);
			} else {
			    return new ECDHWorkflowConfigurationFactory(config);
			}
		    case DHE_DSS:
		    case DHE_RSA:
		    case DH_ANON:
		    case DH_DSS:
		    case DH_RSA:
			if (config.getProtocolVersion() == ProtocolVersion.DTLS10
				|| config.getProtocolVersion() == ProtocolVersion.DTLS12) {
			    return new DtlsDhWorkflowConfigurationFactory(config);
			} else {
			    return new DHWorkflowConfigurationFactory(config);
			}
		    default:
			LOGGER.info("Unsupported key exchange algorithm "
				+ AlgorithmResolver.getKeyExchangeAlgorithm(cs));
			return new UnsupportedWorkflowConfigurationFactory(config);
		}
	    } catch (UnsupportedOperationException ex) {
		LOGGER.info(ex.getLocalizedMessage(), ex);
		return new UnsupportedWorkflowConfigurationFactory(config);
	    }
	}
    }

    /**
     * Creates a basic TLS context with a single ClientHello message
     * 
     * @return
     */
    public TlsContext createClientHelloTlsContext(ConnectionEnd myConnectionEnd) {
	TlsContext context = new TlsContext();
	context.setProtocolVersion(config.getProtocolVersion());

	context.setSelectedCipherSuite(config.getCipherSuites().get(0));
	WorkflowTrace workflowTrace = new WorkflowTrace();

	ClientHelloMessage clientHello = new ClientHelloMessage();
	workflowTrace.add(MessageActionFactory.createAction(myConnectionEnd, ConnectionEnd.CLIENT, clientHello));
	clientHello.setSupportedCipherSuites(config.getCipherSuites());
	clientHello.setSupportedCompressionMethods(config.getCompressionMethods());
	initializeClientHelloExtensions(config, clientHello);
	context.setWorkflowTrace(workflowTrace);
	initializeProtocolMessageOrder(context);

	return context;
    }

    /**
     * Creates a basic TLS context with a TLS handshake messages
     * 
     * @return
     */
    public TlsContext createHandshakeTlsContext(ConnectionEnd myConnectionEnd) {
	TlsContext context = this.createClientHelloTlsContext(myConnectionEnd);
	List<ProtocolMessage> messages = new LinkedList<>();
	WorkflowTrace workflowTrace = context.getWorkflowTrace();

	messages.add(new ServerHelloMessage());
	messages.add(new CertificateMessage());
	messages.add(new ServerHelloDoneMessage());
	workflowTrace.add(MessageActionFactory.createAction(myConnectionEnd, ConnectionEnd.SERVER, messages));
	messages = new LinkedList<>();

	messages.add(new ChangeCipherSpecMessage());
	messages.add(new FinishedMessage());
	workflowTrace.add(MessageActionFactory.createAction(myConnectionEnd, ConnectionEnd.CLIENT, messages));
	messages = new LinkedList<>();
	messages.add(new ChangeCipherSpecMessage());
	messages.add(new FinishedMessage());
	workflowTrace.add(MessageActionFactory.createAction(myConnectionEnd, ConnectionEnd.SERVER, messages));
	initializeProtocolMessageOrder(context);

	return context;
    }

    /**
     * Creates an extended TLS context including an application data and
     * heartbeat messages
     * 
     * @return
     */
    public TlsContext createFullTlsContext(ConnectionEnd myConnectionEnd) {
	TlsContext context = this.createHandshakeTlsContext(myConnectionEnd);
	WorkflowTrace workflowTrace = context.getWorkflowTrace();
	List<ProtocolMessage> messages = new LinkedList<>();
	messages.add(new ApplicationMessage());

	if (config.getHeartbeatMode() != null) {
	    messages.add(new HeartbeatMessage());
	    workflowTrace.add(MessageActionFactory.createAction(myConnectionEnd, ConnectionEnd.CLIENT, messages));
	    messages = new LinkedList<>();
	    messages.add(new HeartbeatMessage());
	    workflowTrace.add(MessageActionFactory.createAction(myConnectionEnd, ConnectionEnd.SERVER, messages));
	} else {
	    workflowTrace.add(MessageActionFactory.createAction(myConnectionEnd, ConnectionEnd.CLIENT, messages));
	}
	initializeProtocolMessageOrder(context);
	return context;
    }

    /**
     * Creates a full TLS context with additional application data
     * ServerResponse
     * 
     * @return
     */
    public TlsContext createFullServerResponseTlsContext(ConnectionEnd myConnectionEnd) {
	TlsContext context = this.createFullTlsContext(myConnectionEnd);
	WorkflowTrace workflowTrace = context.getWorkflowTrace();
	List<ProtocolMessage> messages = new LinkedList<>();
	messages.add(new ApplicationMessage());
	workflowTrace.add(MessageActionFactory.createAction(myConnectionEnd, ConnectionEnd.SERVER, messages));
	initializeProtocolMessageOrder(context);

	return context;
    }

    /**
     * Initializes ClientHello extensions
     * 
     * @param config
     * @param ch
     */
    public static void initializeClientHelloExtensions(CommandConfig config, ClientHelloMessage ch) {
	if (config.getNamedCurves() != null && !config.getNamedCurves().isEmpty()) {
	    EllipticCurvesExtensionMessage ecc = new EllipticCurvesExtensionMessage();
	    ecc.setSupportedCurvesConfig(config.getNamedCurves());
	    ch.addExtension(ecc);
	}

	if (config.getPointFormats() != null && !config.getPointFormats().isEmpty()) {
	    ECPointFormatExtensionMessage pfc = new ECPointFormatExtensionMessage();
	    pfc.setPointFormatsConfig(config.getPointFormats());
	    ch.addExtension(pfc);
	}

	if (config.getHeartbeatMode() != null) {
	    HeartbeatExtensionMessage hem = new HeartbeatExtensionMessage();
	    hem.setHeartbeatModeConfig(config.getHeartbeatMode());
	    ch.addExtension(hem);
	}

	if (config.getServerName() != null) {
	    ServerNameIndicationExtensionMessage sni = new ServerNameIndicationExtensionMessage();
	    sni.setNameTypeConfig(NameType.HOST_NAME);
	    sni.setServerNameConfig(config.getServerName());
	    ch.addExtension(sni);
	}

	if (config.getMaxFragmentLength() != null) {
	    MaxFragmentLengthExtensionMessage mle = new MaxFragmentLengthExtensionMessage();
	    mle.setMaxFragmentLengthConfig(MaxFragmentLength.getMaxFragmentLength(config.getMaxFragmentLength()
		    .byteValue()));
	    ch.addExtension(mle);
	}

	if (config.getSignatureAndHashAlgorithms() != null) {
	    SignatureAndHashAlgorithmsExtensionMessage sae = new SignatureAndHashAlgorithmsExtensionMessage();
	    sae.setSignatureAndHashAlgorithmsConfig(config.getSignatureAndHashAlgorithms());
	    ch.addExtension(sae);
	}
    }

    /**
     * Initializes the preconfigured protocol message order according to the
     * workflow trace. This protocol message order can be used to compare the
     * configured and real message order.
     * 
     * @param context
     */
    public static void initializeProtocolMessageOrder(TlsContext context) {
	List<ProtocolMessageTypeHolder> configuredProtocolMessageOrder = new LinkedList<>();
	for (ProtocolMessage pm : context.getWorkflowTrace().getAllConfiguredMessages()) {
	    ProtocolMessageTypeHolder pmth = new ProtocolMessageTypeHolder(pm);
	    configuredProtocolMessageOrder.add(pmth);
	}
    }

    /**
     * 
     * 
     * @param context
     * @param protocolMessages
     */
    public static void appendProtocolMessagesToWorkflow(TlsContext context, List<ProtocolMessage> protocolMessages) {
	List<ProtocolMessage> configured = context.getWorkflowTrace().getAllConfiguredMessages();
	for (ProtocolMessage pm : protocolMessages) {
	    configured.add(pm);
	}
	initializeProtocolMessageOrder(context);
    }
}
