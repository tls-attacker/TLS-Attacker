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
import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;

public class SrtpExtensionSerializer extends ExtensionSerializer<SrtpExtensionMessage> {

    private final SrtpExtensionMessage msg;

    public SrtpExtensionSerializer(SrtpExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendInt(msg.getSrtpProtectionProfilesLength().getValue(), ExtensionByteLength.SRTP_PROTECTION_PROFILES_LENGTH);
        appendBytes(msg.getSrtpProtectionProfiles().getValue());
        appendInt(msg.getSrtpMkiLength().getValue(), ExtensionByteLength.SRTP_MASTER_KEY_IDENTIFIER_LENGTH);
        if (msg.getSrtpMkiLength().getValue() != 0) {
            appendBytes(msg.getSrtpMki().getValue());
        }

        return getAlreadySerialized();
    }

}
