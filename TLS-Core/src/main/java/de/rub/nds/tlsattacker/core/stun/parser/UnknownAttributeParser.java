package de.rub.nds.tlsattacker.core.stun.parser;

import java.io.InputStream;

import de.rub.nds.tlsattacker.core.stun.IceContext;
import de.rub.nds.tlsattacker.core.stun.model.UnknownAttribute;

public class UnknownAttributeParser extends StunAttributeParser<UnknownAttribute> {

    public UnknownAttributeParser(IceContext context, InputStream stream) {
        super(context, stream);
    }

    @Override
    public void parse(UnknownAttribute attribute) {
        attribute.setUnknownContent(parseTillEnd());
    }    
}
