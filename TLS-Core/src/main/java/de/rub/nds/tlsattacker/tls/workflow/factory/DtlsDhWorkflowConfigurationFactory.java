/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.factory;

import de.rub.nds.tlsattacker.tls.config.CommandConfig;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.application.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.dtls.protocol.handshake.ClientHelloDtlsMessage;
import de.rub.nds.tlsattacker.dtls.protocol.handshake.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.tls.constants.AlertDescription;
import de.rub.nds.tlsattacker.tls.constants.AlertLevel;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.MessageActionFactory;
import java.util.LinkedList;

/**
 * Creates configuration of implemented DH(E) functionality in the protocol.
 * 
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class DtlsDhWorkflowConfigurationFactory extends WorkflowConfigurationFactory {

    public DtlsDhWorkflowConfigurationFactory(CommandConfig config) {
        super(config);
    }

    @Override
    public TlsContext createClientHelloTlsContext(ConnectionEnd myConnectionEnd) {
        TlsContext context = new TlsContext();
        context.setProtocolVersion(config.getProtocolVersion());

        context.setSelectedCipherSuite(config.getCipherSuites().get(0));
        LinkedList<ProtocolMessage> messages = new LinkedList<>();
        WorkflowTrace workflowTrace = new WorkflowTrace();
        ClientHelloDtlsMessage clientHello = new ClientHelloDtlsMessage();
        messages.add(clientHello);

        clientHello.setSupportedCipherSuites(config.getCipherSuites());
        clientHello.setSupportedCompressionMethods(config.getCompressionMethods());
        clientHello.setIncludeInDigest(false);

        initializeClientHelloExtensions(config, clientHello);
        workflowTrace.add(MessageActionFactory.createAction(myConnectionEnd, ConnectionEnd.CLIENT, messages));
        messages = new LinkedList<>();
        HelloVerifyRequestMessage helloVerifyRequestMessage = new HelloVerifyRequestMessage();
        helloVerifyRequestMessage.setIncludeInDigest(false);
        messages.add(helloVerifyRequestMessage);
        workflowTrace.add(MessageActionFactory.createAction(myConnectionEnd, ConnectionEnd.SERVER, messages));
        messages = new LinkedList<>();

        clientHello = new ClientHelloDtlsMessage();
        messages.add(clientHello);

        clientHello.setSupportedCipherSuites(config.getCipherSuites());
        clientHello.setSupportedCompressionMethods(config.getCompressionMethods());

        initializeClientHelloExtensions(config, clientHello);
        workflowTrace.add(MessageActionFactory.createAction(myConnectionEnd, ConnectionEnd.CLIENT, messages));

        context.setWorkflowTrace(workflowTrace);
        initializeProtocolMessageOrder(context);

        return context;
    }

    @Override
    public TlsContext createHandshakeTlsContext(ConnectionEnd myConnectionEnd) {
        TlsContext context = this.createClientHelloTlsContext(myConnectionEnd);

        WorkflowTrace workflowTrace = context.getWorkflowTrace();
        LinkedList<ProtocolMessage> messages = new LinkedList<>();

        messages.add(new ServerHelloMessage());
        messages.add(new CertificateMessage());

        if (config.getCipherSuites().get(0).isEphemeral()) {
            messages.add(new DHEServerKeyExchangeMessage());
        }
        if (config.getKeystore() != null && config.isClientAuthentication()) {
            messages.add(new CertificateRequestMessage());
            messages.add(new ServerHelloDoneMessage());
            workflowTrace.add(MessageActionFactory.createAction(myConnectionEnd, ConnectionEnd.SERVER, messages));
            messages = new LinkedList<>();

            messages.add(new CertificateMessage());
            messages.add(new DHClientKeyExchangeMessage());
            messages.add(new CertificateVerifyMessage());
        } else {
            messages.add(new ServerHelloDoneMessage());

            workflowTrace.add(MessageActionFactory.createAction(myConnectionEnd, ConnectionEnd.SERVER, messages));
            messages = new LinkedList<>();

            messages.add(new DHClientKeyExchangeMessage());
        }
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

    // TODO removed close notify alert from createFullTlsContext

}
