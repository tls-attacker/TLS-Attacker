package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.layer.hints.RecordLayerHint;

public class RetransmissionStruct {

    private final RecordLayerHint hint;

    private final byte[] messageBytes;

    public RetransmissionStruct(RecordLayerHint hint, byte[] messageBytes) {
        this.hint = hint;
        this.messageBytes = messageBytes;
    }

    public RecordLayerHint getHint() {
        return hint;
    }

    public byte[] getMessageBytes() {
        return messageBytes;
    }
}
