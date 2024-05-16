package de.rub.nds.tlsattacker.core.ice.parser;

import java.io.InputStream;

import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.ice.model.ChannelDataMessage;

public class ChannelDataMessageParser extends IceMessageParser<ChannelDataMessage> {

    public ChannelDataMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(ChannelDataMessage message) {
        message.setChannelNumber(parseByteArrayField(IceByteLengths.TURN_CHANNEL_NUMBER));
        message.setMessageLength(parseIntField(IceByteLengths.TURN_CHANNEL_DATA_LENGTH));
        message.setData(parseByteArrayField(message.getMessageLength().getValue()));        
    }

}
