/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.List;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "BufferedReceive")
public class BufferedReceiveAction extends ReceiveAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public BufferedReceiveAction() {
        super();
    }

    public BufferedReceiveAction(
            Set<ActionOption> actionOptions,
            List<ProtocolMessage> expectedMessages,
            List<QuicFrame> expectedQuicFrames,
            List<QuicPacket> quicPackets) {
        super(actionOptions, expectedMessages, expectedQuicFrames, quicPackets);
    }

    public BufferedReceiveAction(ProtocolMessage... expectedMessages) {
        super(expectedMessages);
    }

    public BufferedReceiveAction(QuicFrame... expectedQuicFrames) {
        super(expectedQuicFrames);
    }

    public BufferedReceiveAction(QuicPacket... expectedQuicPackets) {
        super(expectedQuicPackets);
    }

    public BufferedReceiveAction(ActionOption actionOption, QuicFrame... expectedQuicFrames) {
        super(actionOption, expectedQuicFrames);
    }

    public BufferedReceiveAction(ActionOption actionOption, QuicPacket... expectedQuicPackets) {
        super(actionOption, expectedQuicPackets);
    }

    public BufferedReceiveAction(
            ActionOption actionOption,
            List<QuicFrame> expectedQuicFrames,
            List<QuicPacket> expectedQuicPackets) {
        super(actionOption, expectedQuicFrames, expectedQuicPackets);
    }

    public BufferedReceiveAction(
            Set<ActionOption> actionOptions,
            List<QuicFrame> expectedQuicFrames,
            List<QuicPacket> expectedQuicPackets) {
        super(actionOptions, expectedQuicFrames, expectedQuicPackets);
    }

    public BufferedReceiveAction(
            List<ProtocolMessage> expectedMessages, List<HttpMessage> expectedHttpMessages) {
        super(expectedMessages, expectedHttpMessages);
    }

    public BufferedReceiveAction(HttpMessage... expectedHttpMessages) {
        super(expectedHttpMessages);
    }

    public BufferedReceiveAction(
            Set<ActionOption> myActionOptions, List<ProtocolMessage> messages) {
        super(myActionOptions, messages);
    }

    public BufferedReceiveAction(Set<ActionOption> actionOptions, ProtocolMessage... messages) {
        super(actionOptions, messages);
    }

    public BufferedReceiveAction(ActionOption actionOption, ProtocolMessage... messages) {
        super(actionOption, messages);
    }

    public BufferedReceiveAction(String connectionAlias) {
        super(connectionAlias);
    }

    public BufferedReceiveAction(String connectionAliasAlias, List<ProtocolMessage> messages) {
        super(connectionAliasAlias, messages);
    }

    public BufferedReceiveAction(String connectionAliasAlias, ProtocolMessage... messages) {
        super(connectionAliasAlias, messages);
    }

    @Override
    public void execute(State state) {
        super.execute(state);
        TlsContext tlsContext = state.getContext(getConnectionAlias()).getTlsContext();
        tlsContext.getMessageBuffer().addAll(getReceivedMessages());
        tlsContext.getRecordBuffer().addAll(getReceivedRecords());
        LOGGER.debug("New message buffer size: {}", tlsContext.getMessageBuffer().size());
        LOGGER.debug("New record buffer size: {}", tlsContext.getRecordBuffer().size());
    }
}
