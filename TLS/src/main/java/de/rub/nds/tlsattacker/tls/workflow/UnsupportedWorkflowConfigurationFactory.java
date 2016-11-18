/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.tls.config.CommandConfig;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.action.MessageActionFactory;

/**
 * Creates configuration of implemented RSA functionality in the protocol.
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class UnsupportedWorkflowConfigurationFactory extends WorkflowConfigurationFactory {

    private final CommandConfig config;

    public UnsupportedWorkflowConfigurationFactory(CommandConfig config) {
        super(config);
        this.config = config;
    }

    @Override
    public TlsContext createClientHelloTlsContext(ConnectionEnd myConnectionEnd) {
        TlsContext context = new TlsContext();
        context.setProtocolVersion(config.getProtocolVersion());
        context.setSelectedCipherSuite(config.getCipherSuites().get(0));
        WorkflowTrace workflowTrace = new WorkflowTrace();

        ClientHelloMessage clientHello = new ClientHelloMessage();
        workflowTrace.add(MessageActionFactory.createAction(context.getMyConnectionEnd(), ConnectionEnd.CLIENT,
                clientHello));

        clientHello.setSupportedCipherSuites(config.getCipherSuites());
        clientHello.setSupportedCompressionMethods(config.getCompressionMethods());

        initializeClientHelloExtensions(config, clientHello);

        context.setWorkflowTrace(workflowTrace);
        initializeProtocolMessageOrder(context);

        return context;
    }

    @Override
    public TlsContext createHandshakeTlsContext(ConnectionEnd myConnectionEnd) {
        TlsContext context = this.createClientHelloTlsContext(myConnectionEnd);
        WorkflowTrace workflowTrace = context.getWorkflowTrace();

        workflowTrace.add(MessageActionFactory.createAction(context.getMyConnectionEnd(),
                context.getMyConnectionPeer(), new ArbitraryMessage()));

        initializeProtocolMessageOrder(context);

        return context;
    }

    @Override
    public TlsContext createFullTlsContext(ConnectionEnd myConnectionEnd) {
        TlsContext context = this.createHandshakeTlsContext(myConnectionEnd);

        return context;
    }
}
