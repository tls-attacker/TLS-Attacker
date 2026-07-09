/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ice.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.ice.model.ChannelNumberAttribute;

public class ChannelNumberAttributeSerializer
        extends StunAttributeSerializer<ChannelNumberAttribute> {

    public ChannelNumberAttributeSerializer(ChannelNumberAttribute attribute) {
        super(attribute);
    }

    @Override
    public byte[] serializeAttributeContent() {
        int channel =
                attribute.getChannelNumber() != null
                                && attribute.getChannelNumber().getValue() != null
                        ? attribute.getChannelNumber().getValue()
                        : 0x4000; // fallback default within valid range
        int rffu =
                attribute.getRffu() != null && attribute.getRffu().getValue() != null
                        ? attribute.getRffu().getValue()
                        : 0x0000;
        appendBytes(ArrayConverter.intToBytes(channel, 2));
        appendBytes(ArrayConverter.intToBytes(rffu, 2));
        return getAlreadySerialized();
    }
}
