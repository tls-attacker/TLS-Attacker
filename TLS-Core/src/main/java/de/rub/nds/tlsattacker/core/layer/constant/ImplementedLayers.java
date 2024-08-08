/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.constant;

import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2Message;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.record.Record;

/** Holds all implemented layers of the TLS-Core, not limited to any layer of the ISO stack */
public enum ImplementedLayers implements LayerType {
    TCP(null),
    UDP(null),
    // Record + Message layer are both part of TLS
    RECORD(Record.class),
    MESSAGE(ProtocolMessage.class),
    DTLS_FRAGMENT(DtlsHandshakeMessageFragment.class),
    HTTP(HttpMessage.class),
    SSL2(SSL2Message.class),
    QUICPACKET(QuicPacket.class),
    QUICFRAME(QuicFrame.class);

    private Class<?> baseContainerClass;

    private ImplementedLayers(Class<?> baseContainerClass) {
        this.baseContainerClass = baseContainerClass;
    }

    @Override
    public String getName() {
        return this.name();
    }

    @Override
    public Class<?> getBaseContainerClass() {
        return baseContainerClass;
    }
}
