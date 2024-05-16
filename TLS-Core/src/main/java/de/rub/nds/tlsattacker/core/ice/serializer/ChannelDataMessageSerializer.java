package de.rub.nds.tlsattacker.core.ice.serializer;

import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.ice.model.ChannelDataMessage;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;

public class ChannelDataMessageSerializer extends Serializer<ChannelDataMessage>{

        protected final ChannelDataMessage message;

    public ChannelDataMessageSerializer( ChannelDataMessage message) {
        this.message = message;
    }

    @Override
    protected byte[] serializeBytes() {
        appendBytes(message.getChannelNumber().getValue());
        appendInt(message.getMessageLength().getValue(), IceByteLengths.STUN_MESSAGE_LENGTH);
        appendBytes(message.getData().getValue());
        return getAlreadySerialized();
    }
    
}
