/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tcp.TcpStreamContainer;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.udp.UdpDataPacket;
import java.util.List;
import java.util.Set;

public interface SendingAction {

    public abstract List<ProtocolMessage> getSentMessages();

    public abstract List<Record> getSentRecords();

    public abstract List<DtlsHandshakeMessageFragment> getSentFragments();

    public abstract List<QuicPacket> getSentQuicPackets();

    public abstract List<QuicFrame> getSentQuicFrames();

    public abstract List<TcpStreamContainer> getSentTcpStreamContainers();

    public abstract List<UdpDataPacket> getSentUdpDataPackets();

    public Set<String> getAllAliases();

    public Set<String> getAllSendingAliases();
}
