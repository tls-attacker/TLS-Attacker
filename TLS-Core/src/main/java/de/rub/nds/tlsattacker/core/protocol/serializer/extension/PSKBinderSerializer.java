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
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKBinder;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;

public class PSKBinderSerializer extends Serializer<PSKBinder> {

    private final PSKBinder pskBinder;

    public PSKBinderSerializer(PSKBinder pskBinder) {
        this.pskBinder = pskBinder;
    }

    @Override
    protected byte[] serializeBytes() {
        appendInt(pskBinder.getBinderEntryLength().getValue(), ExtensionByteLength.PSK_BINDER_LENGTH);
        appendBytes(pskBinder.getBinderEntry().getValue());

        return getAlreadySerialized();
    }

}
