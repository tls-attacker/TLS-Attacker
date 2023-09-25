/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.hints;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;

public class QuicFrameLayerHint implements LayerProcessingHint {

    private ProtocolMessageType messageType;

    private final boolean firstMessage;

    public QuicFrameLayerHint() {
        this.firstMessage = false;
    }

    public QuicFrameLayerHint(ProtocolMessageType messageType) {
        this.messageType = messageType;
        this.firstMessage = false;
    }

    public QuicFrameLayerHint(ProtocolMessageType messageType, boolean firstMessage) {
        this.messageType = messageType;
        this.firstMessage = firstMessage;
    }

    public ProtocolMessageType getMessageType() {
        return messageType;
    }

    public boolean isFirstMessage() {
        return firstMessage;
    }
}
