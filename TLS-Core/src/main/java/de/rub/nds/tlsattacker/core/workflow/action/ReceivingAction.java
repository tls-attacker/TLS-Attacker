/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.record.Record;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public interface ReceivingAction {

    List<ProtocolMessage> getReceivedMessages();

    List<Record> getReceivedRecords();

    List<DtlsHandshakeMessageFragment> getReceivedFragments();

    List<HttpMessage> getReceivedHttpMessages();

    List<QuicFrame> getReceivedQuicFrames();

    List<QuicPacket> getReceivedQuicPackets();

    default List<ProtocolMessageType> getGoingToReceiveProtocolMessageTypes() {
        return new ArrayList<>();
    }

    default List<HandshakeMessageType> getGoingToReceiveHandshakeMessageTypes() {
        return new ArrayList<>();
    }

    public abstract Set<String> getAllReceivingAliases();
}
