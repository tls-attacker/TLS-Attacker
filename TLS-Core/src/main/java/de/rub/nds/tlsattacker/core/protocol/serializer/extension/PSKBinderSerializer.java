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
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKBinder;

public class PSKBinderSerializer extends Serializer<PSKBinder> {

    private final PSKBinder pskBinder;

    public PSKBinderSerializer(PSKBinder pskBinder) {
        this.pskBinder = pskBinder;
    }

    @Override
    protected byte[] serializeBytes() {
        appendInt(
                pskBinder.getBinderEntryLength().getValue(), ExtensionByteLength.PSK_BINDER_LENGTH);
        appendBytes(pskBinder.getBinderEntry().getValue());

        return getAlreadySerialized();
    }
}
