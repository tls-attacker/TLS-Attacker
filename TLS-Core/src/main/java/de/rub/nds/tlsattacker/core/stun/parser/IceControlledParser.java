package de.rub.nds.tlsattacker.core.stun.parser;

import java.io.InputStream;

import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.stun.IceContext;
import de.rub.nds.tlsattacker.core.stun.model.IceControlledAttribute;

public class IceControlledParser extends StunAttributeParser<IceControlledAttribute> {

    public IceControlledParser(IceContext context, InputStream stream) {
        super(context, stream);
    }

    @Override
    public void parse(IceControlledAttribute attribute) {
        attribute.setTieBreaker(parseByteArrayField(IceByteLengths.STUN_ICE_CONTROLLED_TIE_BREAKER));
    }
    
}
