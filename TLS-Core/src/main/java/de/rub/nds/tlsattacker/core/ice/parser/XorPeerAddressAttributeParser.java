/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ice.parser;

import de.rub.nds.tlsattacker.core.ice.model.XorPeerAddressAttribute;
import de.rub.nds.tlsattacker.core.state.Context;
import java.io.InputStream;

public class XorPeerAddressAttributeParser extends StunAttributeParser<XorPeerAddressAttribute> {

    public XorPeerAddressAttributeParser(Context context, InputStream stream) {
        super(context, stream);
    }

    @Override
    public void parse(XorPeerAddressAttribute attribute) {
        attribute.setReservedByte(parseByteArrayField(1));
        attribute.setProtocolFamily(parseByteArrayField(1));
        attribute.setXorPeerPort(parseByteArrayField(2));
        attribute.setXorPeerIpAddress(parseTillEnd());
    }
}
