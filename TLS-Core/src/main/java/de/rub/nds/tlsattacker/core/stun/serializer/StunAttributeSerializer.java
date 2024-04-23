/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.serializer;

import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.stun.model.StunAttribute;

public abstract class StunAttributeSerializer<AttributeT extends StunAttribute>
        extends Serializer<AttributeT> {

    protected final AttributeT attribute;

    public StunAttributeSerializer(AttributeT attribute) {
        this.attribute = attribute;
    }

    @Override
    protected byte[] serializeBytes() {
        appendBytes(attribute.getAttributeType().getValue());
        appendInt(attribute.getAttributeLength().getValue(), IceByteLengths.STUN_ATTRIBUTE_LENGTH);
        appendBytes(attribute.getBody().getValue());
        return getAlreadySerialized();
    }

    public abstract byte[] serializeAttributeContent();
}
