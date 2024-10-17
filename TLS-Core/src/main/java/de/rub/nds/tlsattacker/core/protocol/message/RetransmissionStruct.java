/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;

public class RetransmissionStruct {

    private final LayerProcessingHint hint;

    private final byte[] messageBytes;

    public RetransmissionStruct(LayerProcessingHint hint, byte[] messageBytes) {
        this.hint = hint;
        this.messageBytes = messageBytes;
    }

    public LayerProcessingHint getHint() {
        return hint;
    }

    public byte[] getMessageBytes() {
        return messageBytes;
    }
}
