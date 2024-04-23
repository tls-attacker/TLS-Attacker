package de.rub.nds.tlsattacker.core.stun.serializer;

import de.rub.nds.tlsattacker.core.stun.model.FingerprintAttribute;

public class FingerprintAttributeSerializer extends StunAttributeSerializer<FingerprintAttribute> {

    public FingerprintAttributeSerializer(FingerprintAttribute attribute) {
        super(attribute);
    }

    @Override
    public byte[] serializeAttributeContent() {
        appendBytes(attribute.getCrcChecksum().getValue());
        return getAlreadySerialized();
    }
    
}
