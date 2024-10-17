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
