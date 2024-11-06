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
import de.rub.nds.tlsattacker.core.ice.model.StunAttribute;
import de.rub.nds.tlsattacker.core.ice.model.StunMessage;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;
import de.rub.nds.tlsattacker.core.state.Context;

public class StunMessageSerializer extends IceMessageSerializer<StunMessage> {

    protected final StunMessage message;

    private IceContext iceContext;

    public StunMessageSerializer(Context context, StunMessage message) {
        this.message = message;
        this.iceContext = context.getIceContext();
    }

    @Override
    protected byte[] serializeBytes() {
        appendBytes(message.getStunMessageTypeBytes().getValue());
        appendInt(message.getMessageLength().getValue(), IceByteLengths.STUN_MESSAGE_LENGTH);
        appendBytes(message.getTransactionId().getValue());
        for (StunAttribute attribute : message.getAttributeList()) {
            appendBytes(attribute.getSerializer(iceContext.getContext()).serialize());
        }
        return getAlreadySerialized();
    }
}
