package de.rub.nds.tlsattacker.core.stun.parser;

import java.io.InputStream;

import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.stun.IceContext;
import de.rub.nds.tlsattacker.core.stun.model.MessageIntegrityAttribute;

public class MessageIntegrityParser extends StunAttributeParser<MessageIntegrityAttribute> {

    public MessageIntegrityParser(IceContext context, InputStream stream) {
        super(context, stream);
    }

    @Override
    public void parse(MessageIntegrityAttribute attribute) {
        attribute.setHmac(parseByteArrayField(IceByteLengths.STUN_MESSAGE_INTEGRITY_HMAC));
    }
    
}
