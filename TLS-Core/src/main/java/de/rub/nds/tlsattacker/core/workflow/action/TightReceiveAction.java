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
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.TightReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2Message;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.*;

@XmlRootElement(name = "TightReceive")
public class TightReceiveAction extends ReceiveAction {

    public TightReceiveAction() {}

    public TightReceiveAction(
            Set<ActionOption> actionOptions,
            List<ProtocolMessage> expectedMessages,
            List<QuicFrame> expectedQuicFrames,
            List<QuicPacket> quicPackets) {
        super(actionOptions, expectedMessages, expectedQuicFrames, quicPackets);
    }

    public TightReceiveAction(List<ProtocolMessage> expectedMessages) {
        super(expectedMessages);
    }

    public TightReceiveAction(ProtocolMessage... expectedMessages) {
        super(expectedMessages);
    }

    public TightReceiveAction(QuicFrame... expectedQuicFrames) {
        super(expectedQuicFrames);
    }

    public TightReceiveAction(QuicPacket... expectedQuicPackets) {
        super(expectedQuicPackets);
    }

    public TightReceiveAction(ActionOption actionOption, QuicFrame... expectedQuicFrames) {
        super(actionOption, expectedQuicFrames);
    }

    public TightReceiveAction(ActionOption actionOption, QuicPacket... expectedQuicPackets) {
        super(actionOption, expectedQuicPackets);
    }

    public TightReceiveAction(
            ActionOption actionOption,
            List<QuicFrame> expectedQuicFrames,
            List<QuicPacket> expectedQuicPackets) {
        super(actionOption, expectedQuicFrames, expectedQuicPackets);
    }

    public TightReceiveAction(
            Set<ActionOption> actionOptions,
            List<QuicFrame> expectedQuicFrames,
            List<QuicPacket> expectedQuicPackets) {
        super(actionOptions, expectedQuicFrames, expectedQuicPackets);
    }

    public TightReceiveAction(
            List<ProtocolMessage> expectedMessages, List<HttpMessage> expectedHttpMessages) {
        super(expectedMessages, expectedHttpMessages);
    }

    public TightReceiveAction(HttpMessage... expectedHttpMessages) {
        super(expectedHttpMessages);
    }

    public TightReceiveAction(Set<ActionOption> myActionOptions, List<ProtocolMessage> messages) {
        super(myActionOptions, messages);
    }

    public TightReceiveAction(Set<ActionOption> actionOptions, ProtocolMessage... messages) {
        super(actionOptions, messages);
    }

    public TightReceiveAction(Set<ActionOption> actionOptions, SSL2Message... messages) {
        super(actionOptions, messages);
    }

    public TightReceiveAction(SSL2Message... messages) {
        super(messages);
    }

    public TightReceiveAction(ActionOption actionOption, List<ProtocolMessage> messages) {
        super(actionOption, messages);
    }

    public TightReceiveAction(ActionOption actionOption, ProtocolMessage... messages) {
        super(actionOption, messages);
    }

    public TightReceiveAction(String connectionAlias) {
        super(connectionAlias);
    }

    public TightReceiveAction(String connectionAliasAlias, List<ProtocolMessage> messages) {
        super(connectionAliasAlias, messages);
    }

    public TightReceiveAction(String connectionAliasAlias, ProtocolMessage... messages) {
        super(connectionAliasAlias, messages);
    }

    @Override
    protected <T extends DataContainer> LayerConfiguration<T> createReceiveLayerConfiguration(
            LayerType type, List<T> containerList) {
        return new TightReceiveLayerConfiguration(type, containerList);
    }
}
