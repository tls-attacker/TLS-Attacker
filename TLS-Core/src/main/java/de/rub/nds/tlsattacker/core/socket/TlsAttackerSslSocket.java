/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.socket;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.UnknownExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.ClientHelloParser;
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
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.List;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

public class TlsAttackerSslSocket extends SSLSocket {

    private State state;
    private final long timeout;

    private final Config config;

    private EncapsulatingInputStream inputStream;

    private EncapsulatingOutputStream outputStream;

    private byte[] clientHelloBytes = null;

    /**
     * Creates a TlsAttackerSslSocket which loads a byte array of a client hello and tries to adapt
     * it.
     *
     * @param config
     * @param hostname
     * @param port
     * @param timeout
     * @param clientHelloBytes the client hello without the record header that should be used
     * @throws IOException
     * @throws UnknownHostException
     */
    public TlsAttackerSslSocket(
            Config config, String hostname, int port, long timeout, byte[] clientHelloBytes)
            throws IOException, UnknownHostException {
        super(hostname, port);
        this.timeout = timeout;
        this.config = config;
        this.clientHelloBytes = clientHelloBytes;
    }

    public TlsAttackerSslSocket(Config config, String hostname, int port, long timeout)
            throws IOException, UnknownHostException {
        super(hostname, port);
        this.timeout = timeout;
        this.config = config;
    }

    public TlsAttackerSslSocket(Config config, InetAddress ia, int port, long timeout)
            throws IOException {
        super(ia, port);
        this.timeout = timeout;
        this.config = config;
    }

    public TlsAttackerSslSocket(
            Config config, String hostname, int port, InetAddress ia, int i1, long timeout)
            throws IOException, UnknownHostException {
        super(hostname, port, ia, i1);
        this.timeout = timeout;
        this.config = config;
    }

    public TlsAttackerSslSocket(
            Config config, InetAddress ia, int port, InetAddress ia1, int i1, long timeout)
            throws IOException {
        super(ia, port, ia1, i1);
        this.timeout = timeout;
        this.config = config;
    }

    @Override
    public String[] getSupportedCipherSuites() {
        String[] cipherSuites = new String[config.getDefaultClientSupportedCipherSuites().size()];
        for (int i = 0; i < cipherSuites.length; i++) {
            cipherSuites[i] = config.getDefaultClientSupportedCipherSuites().get(i).name();
        }
        return cipherSuites;
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return new String[] {"SSL3", "TLS10", "TLS11", "TLS12", "TLS13"};
    }

    @Override
    public void setEnabledCipherSuites(String[] strings) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String[] getSupportedProtocols() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String[] getEnabledProtocols() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void setEnabledProtocols(String[] strings) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public SSLSession getSession() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener hl) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener hl) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void startHandshake() throws IOException {
        config.getDefaultClientConnection().setHostname(this.getInetAddress().getHostName());
        config.getDefaultClientConnection().setIp(this.getInetAddress().getHostAddress());
        config.getDefaultClientConnection().setPort(this.getPort());
        config.setWorkflowExecutorShouldClose(false);
        config.setWorkflowExecutorShouldOpen(false);
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace =
                factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());

        ClientHelloMessage message;
        if (clientHelloBytes == null) {
            message = new ClientHelloMessage(config);
        } else {
            message = createClientHelloFromBytes(clientHelloBytes);
        }
        trace.addTlsAction(new SendAction(message));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloMessage()));

        state = new State(config, trace);
        if (clientHelloBytes != null) {
            for (ExtensionType type : ExtensionType.getImplemented()) {
                state.getTlsContext().addProposedExtension(type);
            }
        }
        StreamTransportHandler streamTransportHandler =
                new StreamTransportHandler(
                        timeout,
                        timeout,
                        ConnectionEndType.CLIENT,
                        super.getInputStream(),
                        super.getOutputStream());
        streamTransportHandler.initialize();
        state.getTlsContext().setTransportHandler(streamTransportHandler);
        WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        executor.executeWorkflow();

        if (trace.executedAsPlanned()) {
            ServerHelloMessage msg =
                    (ServerHelloMessage)
                            WorkflowTraceUtil.getFirstReceivedMessage(
                                    HandshakeMessageType.SERVER_HELLO, trace);
            if (msg.isTls13HelloRetryRequest()) {

                config.setDefaultClientNamedGroups(state.getTlsContext().getSelectedGroup());
                new SendAction(
                                "client",
                                new ChangeCipherSpecMessage(),
                                new ClientHelloMessage(config))
                        .execute(state);

                finishHandshakeTls13(trace);
            } else if (state.getTlsContext().getSelectedProtocolVersion()
                    == ProtocolVersion.TLS13) {
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

    private void finishHandshake(WorkflowTrace trace)
            throws RuntimeException, WorkflowExecutionException {
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace)) {
            ReceiveTillAction receiveTillAction =
                    new ReceiveTillAction("client", new ServerHelloDoneMessage());
            receiveTillAction.execute(state);
            if (!receiveTillAction.executedAsPlanned()) {
                throw new RuntimeException("Did not receive ServerHelloDone");
            }
        }
        new SendDynamicClientKeyExchangeAction("client").execute(state);
        new SendAction("client", new ChangeCipherSpecMessage(), new FinishedMessage())
                .execute(state);
        ReceiveTillAction receiveTillAction =
                new ReceiveTillAction("client", new FinishedMessage());
        receiveTillAction.execute(state);
        if (!receiveTillAction.executedAsPlanned()) {
            throw new RuntimeException("Did not receive FinishedMessage");
        }
    }

    private void finishHandshakeTls13(WorkflowTrace trace) throws RuntimeException {
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, trace)) {
            ReceiveTillAction receiveTillAction =
                    new ReceiveTillAction("client", new FinishedMessage());
            receiveTillAction.execute(state);
            if (!receiveTillAction.executedAsPlanned()) {
                throw new RuntimeException("Did not receive Finished (TLS 1.3)");
            }
        }
        new SendAction("client", new FinishedMessage()).execute(state);
    }

    @Override
    public void setUseClientMode(boolean bln) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean getUseClientMode() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void setNeedClientAuth(boolean bln) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean getNeedClientAuth() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void setWantClientAuth(boolean bln) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean getWantClientAuth() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void setEnableSessionCreation(boolean bln) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean getEnableSessionCreation() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return outputStream;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return inputStream;
    }

    private ClientHelloMessage createClientHelloFromBytes(byte[] clientHelloBytes) {
        ClientHelloMessage message = new ClientHelloMessage();

        ClientHelloParser parser =
                new ClientHelloParser(
                        new ByteArrayInputStream(clientHelloBytes), state.getTlsContext());
        ClientHelloMessage parsedClientHelloMessage = new ClientHelloMessage();
        parser.parse(parsedClientHelloMessage);
        message.setCipherSuites(
                Modifiable.explicit(parsedClientHelloMessage.getCipherSuites().getValue()));
        message.setCompressions(
                Modifiable.explicit(parsedClientHelloMessage.getCompressions().getValue()));
        message.setSessionId(
                Modifiable.explicit(parsedClientHelloMessage.getSessionId().getValue()));
        message.setProtocolVersion(
                Modifiable.explicit(parsedClientHelloMessage.getProtocolVersion().getValue()));
        for (ExtensionMessage parsedExtension : parsedClientHelloMessage.getExtensions()) {
            if (parsedExtension instanceof KeyShareExtensionMessage) {
                // Since we do not know the private key we have to overwrite the
                // keyshare extension - currently only x25519 supported...
                List<KeyShareStoreEntry> storeEntryList = new LinkedList();
                for (KeyShareEntry entry :
                        ((KeyShareExtensionMessage) parsedExtension).getKeyShareList()) {
                    NamedGroup group = NamedGroup.getNamedGroup(entry.getGroup().getValue());
                    if (group.isCurve()) {
                        if (group == NamedGroup.ECDH_X25519) {
                            // TODO this has to be properly added...
                            storeEntryList.add(config.getDefaultClientKeyStoreEntries().get(0));

                        } else {
                            throw new UnsupportedOperationException(
                                    "Keyshares are weired in the current master branch - we will fix this in the next release. Sorry - needs to be added here");
                        }
                    } else {
                        storeEntryList.add(new KeyShareStoreEntry(group, new byte[1]));
                    }
                }
                config.setDefaultClientKeyStoreEntries(storeEntryList);
                KeyShareExtensionMessage recreatedKeyShareExtensionMessage =
                        new KeyShareExtensionMessage(config);
                message.addExtension(recreatedKeyShareExtensionMessage);

            } else {
                UnknownExtensionMessage craftedExtensionMessage = new UnknownExtensionMessage();
                craftedExtensionMessage.setExtensionBytes(
                        Modifiable.explicit(parsedExtension.getExtensionBytes().getValue()));
                message.addExtension(craftedExtensionMessage);
            }
        }
        return message;
    }
}
