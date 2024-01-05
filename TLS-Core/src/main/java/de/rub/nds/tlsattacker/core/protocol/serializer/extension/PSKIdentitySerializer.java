/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKIdentity;

public class PSKIdentitySerializer extends Serializer<PSKIdentity> {

    private final PSKIdentity pskIdentity;

    public PSKIdentitySerializer(PSKIdentity pskIdentity) {
        this.pskIdentity = pskIdentity;
    }

    @Override
    protected byte[] serializeBytes() {
        appendInt(
                pskIdentity.getIdentityLength().getValue(),
                ExtensionByteLength.PSK_IDENTITY_LENGTH);
        appendBytes(pskIdentity.getIdentity().getValue());
        appendBytes(pskIdentity.getObfuscatedTicketAge().getValue());

        return getAlreadySerialized();
    }
}
