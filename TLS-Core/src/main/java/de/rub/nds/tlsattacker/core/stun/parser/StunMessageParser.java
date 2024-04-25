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
import de.rub.nds.tlsattacker.core.constants.stun.StunMessageClass;
import de.rub.nds.tlsattacker.core.constants.stun.StunMethodType;
import de.rub.nds.tlsattacker.core.constants.stun.StunVersionCookie;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.stun.factory.AttributeFactory;
import de.rub.nds.tlsattacker.core.stun.model.StunAttribute;
import de.rub.nds.tlsattacker.core.stun.model.StunMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StunMessageParser extends Parser<StunMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private IceContext context;

    public StunMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(StunMessage stunMessage) {
        stunMessage.setStunMessageType(parseByteArrayField(IceByteLengths.STUN_MESSAGE_TYPE));
        stunMessage.setMessageLength(parseIntField(IceByteLengths.STUN_MESSAGE_LENGTH));
        stunMessage.setTransactionId(parseByteArrayField(IceByteLengths.STUN_TRANSACTION_ID));
        stunMessage.setMagicCookiePresent(isMagicCookiePresent(stunMessage));
        stunMessage.setStunMessageClass(
                new byte[] {
                    StunMessageClass.getMessageClass(
                                    stunMessage.getStunMessageTypeBytes().getValue())
                            .getValue()
                });
        stunMessage.setStunMethodType(
                StunMethodType.getStunMethodTypeFromRawBytes(
                                stunMessage.getStunMessageTypeBytes().getValue())
                        .getValue());
        while (getBytesLeft() > 0) {
            byte[] attributeTypeBytes = parseByteArrayField(IceByteLengths.STUN_ATTRIBUTE_TYPE);
            StunAttributeType attributeType =
                    StunAttributeType.getAttributeType(attributeTypeBytes);
            LOGGER.debug("Parsing: {}", attributeType);
            StunAttribute attribute = AttributeFactory.createAttribute(attributeType);
            attribute.setAttributeType(attributeTypeBytes);
            int attributeLength = parseIntField(IceByteLengths.STUN_ATTRIBUTE_LENGTH);
            attribute.setAttributeLength(attributeLength);
            byte[] attributeBody = parseByteArrayField(attributeLength);
            attribute.setBody(attributeBody);
            byte[] padding =
                    parseByteArrayField(
                            IceByteLengths.STUN_ATTRIBUTE_ALIGNMENT
                                    - attributeLength % IceByteLengths.STUN_ATTRIBUTE_ALIGNMENT);
            attribute.setPadding(padding);
            StunAttributeParser attributeParser = attribute.getParser(context, getStream());
            attributeParser.parse(attribute);
            stunMessage.getAttributeList().add(attribute);
        }
    }

    private boolean isMagicCookiePresent(StunMessage message) {
        // Check if the first 4 bytes of the transaction id match the magic cookie
        byte[] magicCookie = StunVersionCookie.RFC5389_VERSION;
        byte[] transactionId = message.getTransactionId().getValue();
        for (int i = 0; i < 4; i++) {
            if (magicCookie[i] != transactionId[i]) {
                return false;
            }
        }
        return true;
    }
}
