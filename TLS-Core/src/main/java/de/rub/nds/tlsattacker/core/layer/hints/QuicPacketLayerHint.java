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
import java.util.ArrayList;
import java.util.List;

public class QuicPacketLayerHint implements LayerProcessingHint {

    private QuicPacketType quicPacketType;

    private List<Integer> frameBoundaries;

    public QuicPacketLayerHint() {}

    public QuicPacketLayerHint(QuicPacketType quicPacketType) {
        this.quicPacketType = quicPacketType;
        frameBoundaries = new ArrayList<>();
    }

    public QuicPacketType getQuicPacketType() {
        return quicPacketType;
    }

    public List<Integer> getFrameBoundaries() {
        return frameBoundaries;
    }

    public void setFrameBoundaries(List<Integer> frameBoundaries) {
        this.frameBoundaries = frameBoundaries;
    }

    public void addFrameBoundary(int boundary) {
        frameBoundaries.add(boundary);
    }
}
