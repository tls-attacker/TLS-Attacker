/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension.alpn;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.alpn.AlpnEntry;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;

public class AlpnEntrySerializer extends Serializer<AlpnEntry> {

    private final AlpnEntry entry;

    public AlpnEntrySerializer(AlpnEntry entry) {
        this.entry = entry;
    }

    @Override
    protected byte[] serializeBytes() {
        appendInt(entry.getAlpnEntryLength().getValue(), ExtensionByteLength.ALPN_ENTRY_LENGTH);
        appendBytes(entry.getAlpnEntry().getValue().getBytes());
        return getAlreadySerialized();
    }

}
