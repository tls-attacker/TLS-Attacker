/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ice.parser;

import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.ice.model.ChannelDataMessage;
import java.io.InputStream;

public class ChannelDataMessageParser extends IceMessageParser<ChannelDataMessage> {

    public ChannelDataMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(ChannelDataMessage message) {
        // TODO Do not parse channel number for TCP
        message.setChannelNumber(parseByteArrayField(IceByteLengths.TURN_CHANNEL_NUMBER));
        message.setMessageLength(parseIntField(IceByteLengths.TURN_CHANNEL_DATA_LENGTH));
        message.setData(parseByteArrayField(message.getMessageLength().getValue()));
        int paddingLength = 0;
        if (getBytesLeft() > 0) {
            paddingLength =
                    (IceByteLengths.DATA_CHANNEL_ALIGNMENT
                                    - (message.getMessageLength().getValue())
                                            % IceByteLengths.DATA_CHANNEL_ALIGNMENT)
                            % IceByteLengths.DATA_CHANNEL_ALIGNMENT;
            if (paddingLength < 0) {
                paddingLength = 0;
            }
        }

        message.setPadding(parseByteArrayField(paddingLength));
    }
}
