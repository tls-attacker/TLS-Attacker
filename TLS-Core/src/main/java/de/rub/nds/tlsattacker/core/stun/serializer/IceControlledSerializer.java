package de.rub.nds.tlsattacker.core.stun.serializer;

import de.rub.nds.tlsattacker.core.stun.model.IceControlledAttribute;

public class IceControlledSerializer extends StunAttributeSerializer<IceControlledAttribute> {

    public IceControlledSerializer(IceControlledAttribute attribute) {
        super(attribute);
    }

    @Override
    public byte[] serializeAttributeContent() {
        appendBytes(attribute.getTieBreaker().getValue());
        return getAlreadySerialized();
    }
    
}
