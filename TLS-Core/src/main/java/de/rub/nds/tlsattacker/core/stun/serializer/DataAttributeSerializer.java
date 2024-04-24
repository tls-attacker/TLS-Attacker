package de.rub.nds.tlsattacker.core.stun.serializer;

import de.rub.nds.tlsattacker.core.stun.model.DataAttribute;

public class DataAttributeSerializer extends StunAttributeSerializer<DataAttribute>{

    public DataAttributeSerializer(DataAttribute attribute) {
        super(attribute);
    }

    @Override
    public byte[] serializeAttributeContent() {
        appendBytes(attribute.getData().getValue());
        return getAlreadySerialized();
    }
    
}
