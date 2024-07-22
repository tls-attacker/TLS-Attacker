/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ice.serializer;

import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.ice.model.ChannelDataMessage;

public class ChannelDataMessageSerializer extends IceMessageSerializer<ChannelDataMessage> {

    protected final ChannelDataMessage message;

    public ChannelDataMessageSerializer(ChannelDataMessage message) {
        this.message = message;
    }

    @Override
    protected byte[] serializeBytes() {
        // TODO Do not parse channel number for TCP
        appendBytes(message.getChannelNumber().getValue());
        appendInt(message.getMessageLength().getValue(), IceByteLengths.STUN_MESSAGE_LENGTH);
        appendBytes(message.getData().getValue());
        appendBytes(message.getPadding().getValue());
        return getAlreadySerialized();
    }
}
