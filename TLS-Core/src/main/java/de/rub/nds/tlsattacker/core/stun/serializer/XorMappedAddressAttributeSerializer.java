/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.serializer;

import de.rub.nds.tlsattacker.core.stun.model.XorMappedAddressAttribute;

public class XorMappedAddressAttributeSerializer
        extends StunAttributeSerializer<XorMappedAddressAttribute> {

    public XorMappedAddressAttributeSerializer(XorMappedAddressAttribute attribute) {
        super(attribute);
    }

    @Override
    public byte[] serializeAttributeContent() {
        appendBytes(attribute.getReservedByte().getValue());
        appendBytes(attribute.getProtocolFamily().getValue());
        appendBytes(attribute.getXorMappedPort().getValue());
        appendBytes(attribute.getXorMappedIpAddress().getValue());
        return getAlreadySerialized();
    }
}
