/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.component.action;

import static org.junit.Assert.assertTrue;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeUdpTransportHandler;
import de.rub.nds.tlsattacker.core.workflow.DTLSWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import java.security.Security;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** Component test that covers forward actions in fragmented DTLS */
public class ActionComponentTest {

    protected static final String SERVER_CTX_ALIAS = "serverctx";
    protected static final String CLIENT_CTX_ALIAS = "clientctx";

    private final Config config;
    private FakeUdpTransportHandler serverTransportHandler;
    private FakeUdpTransportHandler clientTransportHandler;

    private final List<AliasedConnection> connectionList;

    public ActionComponentTest() {
        Security.addProvider(new BouncyCastleProvider());
        this.config = new Config();
        this.config.setDefaultLayerConfiguration(StackConfiguration.DTLS);
        this.config.setHighestProtocolVersion(ProtocolVersion.DTLS12);
        this.config.setDefaultSelectedProtocolVersion(ProtocolVersion.DTLS12);
        this.config.setInitialRecordVersion(ProtocolVersion.DTLS10);
        this.config.setIndividualTransportPacketsForFragments(true);
        InboundConnection serverConnection =
                new InboundConnection(SERVER_CTX_ALIAS, 0, "127.0.0.1");
        serverConnection.setTransportHandlerType(TransportHandlerType.UDP);
        serverConnection.setConnectionTimeout(0);
        serverConnection.setTimeout(0);
        OutboundConnection clientConnection =
                new OutboundConnection(CLIENT_CTX_ALIAS, 0, "127.0.0.1");
        clientConnection.setTransportHandlerType(TransportHandlerType.UDP);
        clientConnection.setConnectionTimeout(0);
        clientConnection.setTimeout(0);
        this.config.setDefaultServerConnection(serverConnection);
        this.config.setDefaultClientConnection(clientConnection);

        connectionList = List.of(serverConnection, clientConnection);
    }

    protected WorkflowTrace createTrace() {
        return new WorkflowTrace(connectionList);
    }

    protected void assertDataWrittenToClient() {
        assertTrue(clientTransportHandler.getSentBytes().length > 0);
    }

    protected void assertDataWrittenToServer() {
        assertTrue(serverTransportHandler.getSentBytes().length > 0);
    }

    protected void initAndExecute(
            WorkflowTrace trace, byte[] udpClientPayload, byte[] udpServerPayload) {
        serverTransportHandler = new FakeUdpTransportHandler(ConnectionEndType.SERVER);
        clientTransportHandler = new FakeUdpTransportHandler(ConnectionEndType.CLIENT);
        serverTransportHandler.setFetchableByte(udpServerPayload);
        clientTransportHandler.setFetchableByte(udpClientPayload);

        trace.reset();

        State state = new State(config, trace);

        state.getTlsContext(SERVER_CTX_ALIAS).setTransportHandler(serverTransportHandler);
        state.getTlsContext(CLIENT_CTX_ALIAS).setTransportHandler(clientTransportHandler);
        state.getConfig().setWorkflowExecutorShouldOpen(false);
        state.getConfig().setWorkflowExecutorShouldClose(false);

        new DTLSWorkflowExecutor(state).executeWorkflow();
    }
}
