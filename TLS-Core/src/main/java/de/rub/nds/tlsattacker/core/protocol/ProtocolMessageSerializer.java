package de.rub.nds.tlsattacker.core.protocol;


public abstract class ProtocolMessageSerializer<T extends ProtocolMessage> extends Serializer<T> {
    protected final T message;

    public ProtocolMessageSerializer(T message) {
        this.message = message;
    }

    @Override
    protected final byte[] serializeBytes() {
        return serializeProtocolMessageContent();
    }

    public abstract byte[] serializeProtocolMessageContent();
}
