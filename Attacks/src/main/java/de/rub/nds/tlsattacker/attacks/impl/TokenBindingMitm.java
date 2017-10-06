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
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
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
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ForwardAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TLSAction;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
public class TokenBindingMitm extends Attacker<TokenBindingMitmCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(SimpleMitmProxy.class);

    public TokenBindingMitm(TokenBindingMitmCommandConfig config) {
        super(config, false);

    }

    @Override
    public void executeAttack() {

        Config conf = config.createConfig();
        conf.setQuickReceive(true);

        List<ConnectionEnd> conEnds = conf.getConnectionEnds();
        if (conEnds.size() != 2) {
            throw new ConfigurationException("This attack can only handle one client and one"
                    + " server connection, but more than two connection ends are defined.");
        }

        WorkflowTrace trace = new WorkflowTrace();
        trace.setConnectionEnds(conEnds);
        State state = new State(conf, trace);

        // client -> mitm
        TlsContext clientConCtx = state.getListeningTlsContexts().get(0);
        String clientConAlias = clientConCtx.getConnectionEnd().getAlias();
        // mitm -> server
        TlsContext serverConCtx = state.getConnectingTlsContexts().get(0);
        String serverConAlias = serverConCtx.getConnectionEnd().getAlias();
        //
        // state.clearTlsContexts();
        // state.addTlsContext(clientConAlias, clientConCtx);
        // state.addTlsContext(serverConAlias, serverConCtx);

        // Build a simple rsa TLS 1.2 workflow (no ephemeral KE, no client auth)
        // from client

        TLSAction action = new ReceiveAction(new ClientHelloMessage(conf));
        action.setContextAlias(clientConAlias);
        trace.addTlsAction(action);

        // to server
        action = new SendAction(new ClientHelloMessage(conf));
        action.setContextAlias(serverConAlias);
        trace.addTlsAction(action);

        // from client
        List<ProtocolMessage> messages = new LinkedList<>();
        messages.add(new ServerHelloMessage(conf));
        messages.add(new CertificateMessage(conf));
        messages.add(new ServerHelloDoneMessage(conf));
        action = new SendAction(messages);
        action.setContextAlias(clientConAlias);
        trace.addTlsAction(action);

        // to server
        messages = new LinkedList<>();
        messages.add(new ServerHelloMessage(conf));
        messages.add(new CertificateMessage(conf));
        messages.add(new ServerHelloDoneMessage(conf));
        action = new ReceiveAction(messages);
        action.setContextAlias(serverConAlias);
        trace.addTlsAction(action);

        // from client
        messages = new LinkedList<>();
        messages.add(new RSAClientKeyExchangeMessage(conf));
        messages.add(new ChangeCipherSpecMessage(conf));
        messages.add(new FinishedMessage(conf));
        action = new ReceiveAction(messages);
        action.setContextAlias(clientConAlias);
        trace.addTlsAction(action);

        // to server
        messages = new LinkedList<>();
        messages.add(new RSAClientKeyExchangeMessage(conf));
        messages.add(new ChangeCipherSpecMessage(conf));
        messages.add(new FinishedMessage(conf));
        action = new SendAction(messages);
        action.setContextAlias(serverConAlias);
        trace.addTlsAction(action);

        // to client
        messages = new LinkedList<>();
        messages.add(new ChangeCipherSpecMessage(conf));
        messages.add(new FinishedMessage(conf));
        action = new SendAction(messages);
        action.setContextAlias(clientConAlias);
        trace.addTlsAction(action);

        ApplicationMessage appMsg = new ApplicationMessage(conf);
        ForwardAction f = new ForwardAction(appMsg);
        f.setReceiveFromAlias(clientConAlias);
        f.setForwardToAlias(serverConAlias);
        trace.addTlsAction(f);

        state.setWorkflowTrace(trace);

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
