/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TrustedCaIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.trustedauthority.TrustedAuthority;

public class TrustedCaIndicationExtensionSerializer extends ExtensionSerializer<TrustedCaIndicationExtensionMessage> {

    private final TrustedCaIndicationExtensionMessage msg;

    public TrustedCaIndicationExtensionSerializer(TrustedCaIndicationExtensionMessage message) {
        super(message);
        msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendInt(msg.getTrustedAuthoritiesLength().getValue(), ExtensionByteLength.TRUSTED_AUTHORITY_LIST_LENGTH);

        for (TrustedAuthority ta : msg.getTrustedAuthorities()) {
            TrustedAuthoritySerializer serializer = new TrustedAuthoritySerializer(ta);
            appendBytes(serializer.serialize());
        }

        return getAlreadySerialized();
    }

}
