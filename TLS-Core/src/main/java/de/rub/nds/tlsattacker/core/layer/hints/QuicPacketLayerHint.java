/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.hints;

import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;

public class QuicPacketLayerHint implements LayerProcessingHint {

    private final QuicPacketType quicPacketType;

    private final boolean newPacket;

    public QuicPacketLayerHint() {
        quicPacketType = QuicPacketType.UNKNOWN;
        newPacket = false;
    }

    public QuicPacketLayerHint(QuicPacketType quicPacketType) {
        this.quicPacketType = quicPacketType;
        this.newPacket = false;
    }

    public QuicPacketLayerHint(QuicPacketType quicPacketType, boolean newPacket) {
        this.quicPacketType = quicPacketType;
        this.newPacket = newPacket;
    }

    public QuicPacketType getQuicPacketType() {
        return quicPacketType;
    }

    public boolean isNewPacket() {
        return newPacket;
    }

    public QuicPacketLayerHint asNewPacket(boolean newPacket) {
        return new QuicPacketLayerHint(quicPacketType, newPacket);
    }
}
