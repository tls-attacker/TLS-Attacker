package de.rub.nds.tlsattacker.core.stun.serializer;

import de.rub.nds.tlsattacker.core.stun.model.UnknownAttribute;

public class UnknownAttributeSerializer extends StunAttributeSerializer<UnknownAttribute>{

    public UnknownAttributeSerializer(UnknownAttribute attribute) {
        super(attribute);
    }

    @Override
    public byte[] serializeAttributeContent() {
        appendBytes(attribute.getUnknownContent().getValue());
        return getAlreadySerialized();
    }
    
}
