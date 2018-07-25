package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.GOSTClientKeyExchangeMessage;

public class GOSTClientKeyExchangeSerializer extends ClientKeyExchangeSerializer<GOSTClientKeyExchangeMessage> {

    public GOSTClientKeyExchangeSerializer(GOSTClientKeyExchangeMessage message, ProtocolVersion version) {
        super(message, version);
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        return new byte[0];
    }

}
