/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.parser;

import de.rub.nds.tlsattacker.core.stun.IceContext;
import de.rub.nds.tlsattacker.core.stun.model.XorMappedAddressAttribute;
import java.io.InputStream;

public class XorMappedAttributeParser extends StunAttributeParser<XorMappedAddressAttribute> {

    public XorMappedAttributeParser(IceContext context, InputStream stream) {
        super(context, stream);
    }

    @Override
    public void parse(XorMappedAddressAttribute attribute) {
        attribute.setReservedByte(parseByteArrayField(1));
        attribute.setProtocolFamily(parseByteArrayField(1));
        attribute.setXorMappedPort(parseByteArrayField(2));
        attribute.setXorMappedIpAddress(parseTillEnd());
    }
}
