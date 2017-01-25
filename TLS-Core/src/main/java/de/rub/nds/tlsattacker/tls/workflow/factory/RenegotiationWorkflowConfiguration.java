/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.factory;

import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.application.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import static de.rub.nds.tlsattacker.tls.workflow.factory.WorkflowConfigurationFactory.initializeProtocolMessageOrder;
import de.rub.nds.tlsattacker.tls.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.tls.workflow.action.MessageActionFactory;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.tls.workflow.action.TLSAction;
import java.util.LinkedList;
import java.util.List;

/**
 * Creates Workflowtrace for Renegotiation with Client Authentication
 * 
 * @author Philip Riese <philip.riese@rub.de>
 */
public class RenegotiationWorkflowConfiguration {
    // TODO Shouldnt this extend the WorkflowConfigurationFactiory?
    private final TlsContext tlsContext;

    public RenegotiationWorkflowConfiguration(TlsContext tlsContext) {
        this.tlsContext = tlsContext;
    }

    public void createWorkflow() {
        MessageAction action = tlsContext.getWorkflowTrace().getLastMessageAction();
        WorkflowTrace workflowTrace;
        if (action.getConfiguredMessages().get(action.getConfiguredMessages().size() - 1).getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
            workflowTrace = createHandshakeWorkflow();
        } else if (action.getConfiguredMessages().get(action.getConfiguredMessages().size() - 1)
                .getProtocolMessageType() == ProtocolMessageType.APPLICATION_DATA
                && ((tlsContext.getMyConnectionEnd() == ConnectionEnd.CLIENT && action instanceof SendAction) || (tlsContext
                        .getMyConnectionEnd() == ConnectionEnd.SERVER && action instanceof ReceiveAction))) {
            workflowTrace = createFullWorkflow();
        } else {
            workflowTrace = createFullSRWorkflow();
        }

        tlsContext.setWorkflowTrace(workflowTrace);

        initializeProtocolMessageOrder(tlsContext);

        tlsContext.setRenegotiation(true);
    }

    private WorkflowTrace createHandshakeWorkflow() {

        WorkflowTrace workflowTrace = new WorkflowTrace();

        List<ProtocolMessage> protocolMessages = new LinkedList<>();

        ClientHelloMessage clientHello = new ClientHelloMessage();
        workflowTrace.add(MessageActionFactory.createAction(tlsContext.getMyConnectionEnd(), ConnectionEnd.CLIENT,
                clientHello));
        List<CipherSuite> ciphers = new LinkedList<>();
        ciphers.add(tlsContext.getSelectedCipherSuite());
        clientHello.setSupportedCipherSuites(ciphers);
        List<CompressionMethod> compressions = new LinkedList<>();
        compressions.add(CompressionMethod.NULL);
        clientHello.setSupportedCompressionMethods(compressions);

        protocolMessages.add(new ServerHelloMessage());
        protocolMessages.add(new CertificateMessage());

        if (tlsContext.getSelectedCipherSuite().isEphemeral()) {
            if (tlsContext.getSelectedCipherSuite().name().contains("_DHE_")) {
                protocolMessages.add(new DHEServerKeyExchangeMessage());
            } else {
                protocolMessages.add(new ECDHEServerKeyExchangeMessage());
            }
        }

        if (tlsContext.isClientAuthentication()) {
            protocolMessages.add(new CertificateRequestMessage());
        }

        protocolMessages.add(new ServerHelloDoneMessage());
        workflowTrace.add(MessageActionFactory.createAction(tlsContext.getMyConnectionEnd(), ConnectionEnd.SERVER,
                protocolMessages));
        protocolMessages = new LinkedList<>();
        if (tlsContext.isClientAuthentication()) {
            protocolMessages.add(new CertificateMessage());
        }

        if (tlsContext.getSelectedCipherSuite().name().contains("_DH")) {
            protocolMessages.add(new DHClientKeyExchangeMessage());
        } else if (tlsContext.getSelectedCipherSuite().name().contains("_ECDH")) {
            protocolMessages.add(new ECDHClientKeyExchangeMessage());
        } else {
            protocolMessages.add(new RSAClientKeyExchangeMessage());
        }

        if (tlsContext.isClientAuthentication()) {
            protocolMessages.add(new CertificateVerifyMessage());
        }

        protocolMessages.add(new ChangeCipherSpecMessage());
        protocolMessages.add(new FinishedMessage());
        workflowTrace.add(MessageActionFactory.createAction(tlsContext.getMyConnectionEnd(), ConnectionEnd.CLIENT,
                protocolMessages));
        protocolMessages = new LinkedList<>();
        protocolMessages.add(new ChangeCipherSpecMessage());
        protocolMessages.add(new FinishedMessage());
        workflowTrace.add(MessageActionFactory.createAction(tlsContext.getMyConnectionEnd(), ConnectionEnd.SERVER,
                protocolMessages));
        return workflowTrace;

    }

    private WorkflowTrace createFullWorkflow() {

        WorkflowTrace workflowTrace = this.createHandshakeWorkflow();
        workflowTrace.add(MessageActionFactory.createAction(tlsContext.getMyConnectionEnd(), ConnectionEnd.CLIENT,
                new ApplicationMessage()));

        return workflowTrace;
    }

    private WorkflowTrace createFullSRWorkflow() {

        WorkflowTrace workflowTrace = this.createFullWorkflow();
        workflowTrace.add(MessageActionFactory.createAction(tlsContext.getMyConnectionEnd(), ConnectionEnd.SERVER,
                new ApplicationMessage()));
        return workflowTrace;
    }

}
