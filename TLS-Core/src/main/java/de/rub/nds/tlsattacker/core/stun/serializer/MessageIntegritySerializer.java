package de.rub.nds.tlsattacker.core.stun.serializer;

import de.rub.nds.tlsattacker.core.stun.model.MessageIntegrityAttribute;

public class MessageIntegritySerializer extends StunAttributeSerializer<MessageIntegrityAttribute>  {

    public MessageIntegritySerializer(MessageIntegrityAttribute attribute) {
        super(attribute);
    }

    @Override
    public byte[] serializeAttributeContent() {
        appendBytes(attribute.getHmac().getValue());
        return getAlreadySerialized();
    }
    
}
