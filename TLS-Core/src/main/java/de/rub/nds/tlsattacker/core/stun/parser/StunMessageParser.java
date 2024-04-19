/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.parser;

import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.constants.stun.StunAttributeType;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.stun.IceContext;
import de.rub.nds.tlsattacker.core.stun.factory.AttributeFactory;
import de.rub.nds.tlsattacker.core.stun.model.StunAttribute;
import de.rub.nds.tlsattacker.core.stun.model.StunMessage;
import java.io.InputStream;

public class StunMessageParser extends Parser<StunMessage> {

    private IceContext context;

    public StunMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(StunMessage stunMessage) {
        stunMessage.setStunMessageType(parseByteArrayField(IceByteLengths.STUN_MESSAGE_TYPE));
        stunMessage.setMessageLength(parseIntField(IceByteLengths.STUN_MESSAGE_LENGTH));
        stunMessage.setMagicCookie(parseByteArrayField(IceByteLengths.STUN_MAGIC_COOKIE));
        stunMessage.setTransactionId(parseByteArrayField(IceByteLengths.STUN_TRANSACTION_ID));
        while (getBytesLeft() > 0) {
            byte[] attributeTypeBytes = parseByteArrayField(IceByteLengths.STUN_ATTRIBUTE_TYPE);
            StunAttributeType attributeType =
                    StunAttributeType.getAttributeType(attributeTypeBytes);
            StunAttribute attribute = AttributeFactory.createAttribute(attributeType);
            attribute.getParser(context, getStream()).parse(attribute);
            stunMessage.getAttributeList().add(attribute);
        }
    }
}
