/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsattacker.core.socket;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.stream.StreamTransportHandler;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 *
 * @author ic0ns
 */
public class TlsAttackerSslSocket extends SSLSocket {

    private State state;
    private long timeout;

    private Config config;

    private EncapsulatingInputStream inputStream;

    private EncapsulatingOutputStream outputStream;

    private boolean randomizeConnection;

    public TlsAttackerSslSocket(Config config, String hostname, int port, long timeout) throws IOException,
            UnknownHostException {
        super(hostname, port);
        this.timeout = timeout;
        this.config = config;
    }

    public TlsAttackerSslSocket(Config config, InetAddress ia, int port, long timeout) throws IOException {
        super(ia, port);
        this.timeout = timeout;
        this.config = config;
    }

    public TlsAttackerSslSocket(Config config, String hostname, int port, InetAddress ia, int i1, long timeout)
            throws IOException, UnknownHostException {
        super(hostname, port, ia, i1);
        this.timeout = timeout;
        this.config = config;
    }

    public TlsAttackerSslSocket(Config config, InetAddress ia, int port, InetAddress ia1, int i1, long timeout)
            throws IOException {
        super(ia, port, ia1, i1);
        this.timeout = timeout;
        this.config = config;
    }

    @Override
    public String[] getSupportedCipherSuites() {
        String[] cipherSuites = new String[config.getDefaultClientSupportedCiphersuites().size()];
        for (int i = 0; i < cipherSuites.length; i++) {
            cipherSuites[i] = config.getDefaultClientSupportedCiphersuites().get(i).name();
        }
        return cipherSuites;
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return new String[] { "SSL3", "TLS10", "TLS11", "TLS12", "TLS13" };
    }

    @Override
    public void setEnabledCipherSuites(String[] strings) {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    public String[] getSupportedProtocols() {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    public String[] getEnabledProtocols() {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    public void setEnabledProtocols(String[] strings) {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    public SSLSession getSession() {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener hl) {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener hl) {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    public void startHandshake() throws IOException {
        config.getDefaultClientConnection().setHostname(this.getInetAddress().getHostName());
        config.getDefaultClientConnection().setIp(this.getInetAddress().getHostAddress());
        config.getDefaultClientConnection().setPort(this.getPort());
        config.setWorkflowExecutorShouldClose(false);
        config.setWorkflowExecutorShouldOpen(false);
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace = factory.createTlsEntryWorkflowtrace(config.getDefaultClientConnection());
        ClientHelloMessage message = new ClientHelloMessage();
        trace.addTlsAction(new SendAction(message));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloMessage()));

        state = new State(config, trace);
        StreamTransportHandler streamTransportHandler = new StreamTransportHandler(timeout, ConnectionEndType.CLIENT,
                super.getInputStream(), super.getOutputStream());
        streamTransportHandler.initialize();
        state.getTlsContext().setTransportHandler(streamTransportHandler);
        WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        executor.executeWorkflow();

        if (trace.executedAsPlanned()) {
            ServerHelloMessage msg = (ServerHelloMessage) WorkflowTraceUtil.getFirstReceivedMessage(
                    HandshakeMessageType.SERVER_HELLO, trace);
            if (msg.isTls13HelloRetryRequest()) {

                config.setDefaultClientNamedGroups(state.getTlsContext().getSelectedGroup());
                ;
                new SendAction("client", new ChangeCipherSpecMessage(), new ClientHelloMessage(config)).execute(state);

                finishHandshakeTls13(trace);
            } else if (state.getTlsContext().getSelectedProtocolVersion() == ProtocolVersion.TLS13) {
                finishHandshakeTls13(trace);
            } else {
                finishHandshake(trace);
            }
        } else {
            throw new RuntimeException("Did not receive ServerHello");
        }
        inputStream = new EncapsulatingInputStream(state);
        outputStream = new EncapsulatingOutputStream(state);
    }

    private void finishHandshake(WorkflowTrace trace) throws RuntimeException, WorkflowExecutionException {
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace)) {
            ReceiveTillAction receiveTillAction = new ReceiveTillAction("client", new ServerHelloDoneMessage());
            receiveTillAction.execute(state);
            if (!receiveTillAction.executedAsPlanned()) {
                throw new RuntimeException("Did not receive ServerHelloDone");
            }
        }
        new SendDynamicClientKeyExchangeAction("client").execute(state);
        new SendAction("client", new ChangeCipherSpecMessage(), new FinishedMessage()).execute(state);
        ReceiveTillAction receiveTillAction = new ReceiveTillAction("client", new FinishedMessage());
        receiveTillAction.execute(state);
        if (!receiveTillAction.executedAsPlanned()) {
            throw new RuntimeException("Did not receive FinishedMessage");
        }
    }

    private void finishHandshakeTls13(WorkflowTrace trace) throws RuntimeException {
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, trace)) {
            ReceiveTillAction receiveTillAction = new ReceiveTillAction("client", new FinishedMessage());
            receiveTillAction.execute(state);
            if (!receiveTillAction.executedAsPlanned()) {
                throw new RuntimeException("Did not receive Finished (TLS 1.3)");
            }
        }
        new SendAction("client", new FinishedMessage()).execute(state);
    }

    @Override
    public void setUseClientMode(boolean bln) {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    public boolean getUseClientMode() {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    public void setNeedClientAuth(boolean bln) {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    public boolean getNeedClientAuth() {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    public void setWantClientAuth(boolean bln) {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    public boolean getWantClientAuth() {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    public void setEnableSessionCreation(boolean bln) {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    public boolean getEnableSessionCreation() {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return outputStream;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return inputStream;
    }

}
