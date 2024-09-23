/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension.quic;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParameterEntry;

public class QuicTransportParametersEntrySerializer
        extends Serializer<QuicTransportParameterEntry> {

    public final QuicTransportParameterEntry entry;

    public QuicTransportParametersEntrySerializer(QuicTransportParameterEntry entry) {
        this.entry = entry;
    }

    @Override
    protected byte[] serializeBytes() {
        appendByte(entry.getEntryType().getValue());
        appendInt(
                entry.getEntryLength().getValue(), ExtensionByteLength.QUIC_PARAMETER_ENTRY_LENGTH);
        appendBytes(entry.getEntryValue().getValue());
        return getAlreadySerialized();
    }
}
