package de.rub.nds.tlsattacker.core.stun.parser;

import java.io.InputStream;

import de.rub.nds.tlsattacker.core.stun.IceContext;
import de.rub.nds.tlsattacker.core.stun.model.DataAttribute;

public class DataAttributeParser extends StunAttributeParser<DataAttribute> {

    public DataAttributeParser(IceContext context, InputStream stream) {
        super(context, stream);
    }

    @Override
    public void parse(DataAttribute attribute) {
        attribute.setData(parseTillEnd());
    }
    
}
