package de.rub.nds.tlsattacker.core.stun.serializer;

import de.rub.nds.tlsattacker.core.stun.model.ErrorCodeAttribute;

public class ErrorCodeAttributeSerializer extends StunAttributeSerializer<ErrorCodeAttribute>{

    public ErrorCodeAttributeSerializer(ErrorCodeAttribute attribute) {
        super(attribute);
    }

    @Override
    public byte[] serializeAttributeContent() {
        appendBytes(attribute.getReservedBytes().getValue());
        appendBytes(attribute.getErrorCodeClass().getValue());
        appendBytes(attribute.getErrorCodeLowerValue().getValue());
        appendBytes(attribute.getReasonPhrase().getValue().getBytes());
        return getAlreadySerialized();
    }
    
}
