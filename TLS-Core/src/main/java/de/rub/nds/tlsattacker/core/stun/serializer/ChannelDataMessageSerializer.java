package de.rub.nds.tlsattacker.core.stun.serializer;

import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.stun.model.ChannelDataMessage;

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
