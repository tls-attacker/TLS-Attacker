package de.rub.nds.tlsattacker.core.https;

import de.rub.nds.tlsattacker.core.protocol.Serializer;

public abstract class HttpsMessageSerializer<T extends HttpsMessage> extends Serializer<T> {

    protected final T message;

    public HttpsMessageSerializer(T message) {
        this.message = message;
    }

    public abstract byte[] serializeHttpsMessageContent();

}
