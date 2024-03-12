/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2Message;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.tcp.TcpStreamContainer;
import de.rub.nds.tlsattacker.core.udp.UdpDataPacket;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

@XmlRootElement
public class DummySendingAction extends MessageAction
        implements SendingAction, StaticSendingAction {

    private List<ProtocolMessage> configuredMessages;

    public DummySendingAction() {
        super();
    }

    public DummySendingAction(List<ProtocolMessage> configuredMessages) {
        super();
        this.configuredMessages = configuredMessages;
    }

    public DummySendingAction(ProtocolMessage... configuredMessages) {
        super();
        this.configuredMessages = List.of(configuredMessages);
    }

    @Override
    public List<ProtocolMessage> getSentMessages() {
        return configuredMessages;
    }

    @Override
    public MessageActionDirection getMessageDirection() {
        return MessageActionDirection.SENDING;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {}

    @Override
    public boolean executedAsPlanned() {
        return true;
    }

    @Override
    public List<List<DataContainer<?>>> getConfiguredDataContainerLists() {
        List<List<DataContainer<?>>> lists = new LinkedList<>();
        lists.add((List<DataContainer<?>>) (List<?>) configuredMessages);
        return lists;
    }

    @Override
    public List<SSL2Message> getSentSSL2Messages() {
        throw new UnsupportedOperationException("Unimplemented method 'getSentSSL2Messages'");
    }

    @Override
    public List<Record> getSentRecords() {
        throw new UnsupportedOperationException("Unimplemented method 'getSentRecords'");
    }

    @Override
    public List<DtlsHandshakeMessageFragment> getSentFragments() {
        throw new UnsupportedOperationException("Unimplemented method 'getSentFragments'");
    }

    @Override
    public List<QuicPacket> getSentQuicPackets() {
        throw new UnsupportedOperationException("Unimplemented method 'getSentQuicPackets'");
    }

    @Override
    public List<QuicFrame> getSentQuicFrames() {
        throw new UnsupportedOperationException("Unimplemented method 'getSentQuicFrames'");
    }

    @Override
    public List<TcpStreamContainer> getSentTcpStreamContainers() {
        throw new UnsupportedOperationException(
                "Unimplemented method 'getSentTcpStreamContainers'");
    }

    @Override
    public List<UdpDataPacket> getSentUdpDataPackets() {
        throw new UnsupportedOperationException("Unimplemented method 'getSentUdpDataPackets'");
    }

    @Override
    public Set<String> getAllSendingAliases() {
        throw new UnsupportedOperationException("Unimplemented method 'getAllSendingAliases'");
    }

    public List<ProtocolMessage> getConfiguredMessages() {
        return configuredMessages;
    }

    public void setConfiguredMessages(List<ProtocolMessage> configuredMessages) {
        this.configuredMessages = configuredMessages;
    }

    public void setConfiguredMessages(ProtocolMessage... configuredMessages) {
        this.configuredMessages = List.of(configuredMessages);
    }
}
