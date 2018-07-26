package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.GOSTClientKeyExchangeMessage;
import java.io.IOException;

public class GOSTClientKeyExchangeSerializer extends ClientKeyExchangeSerializer<GOSTClientKeyExchangeMessage> {

    private GOSTClientKeyExchangeMessage message;

    public GOSTClientKeyExchangeSerializer(GOSTClientKeyExchangeMessage message, ProtocolVersion version) {
        super(message, version);
        this.message = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing GOSTClientKeyExchangeMessage");
        try {
            appendBytes(message.getKeyTransportBlob().getEncoded());
        } catch (IOException e) {
            LOGGER.error("Could not get encoded transport blob.", e);
        }
        return getAlreadySerialized();
    }

}
