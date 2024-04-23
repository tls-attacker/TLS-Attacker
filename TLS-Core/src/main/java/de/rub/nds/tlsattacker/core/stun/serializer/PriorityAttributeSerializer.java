package de.rub.nds.tlsattacker.core.stun.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.stun.model.PriorityAttribute;

public class PriorityAttributeSerializer extends StunAttributeSerializer<PriorityAttribute> {

    public PriorityAttributeSerializer(PriorityAttribute attribute) {
        super(attribute);
    }

    @Override
    public byte[] serializeAttributeContent() {
        appendBytes(ArrayConverter.longToUint32Bytes(attribute.getPriority().getValue()));
        return getAlreadySerialized();
    }
    
}
