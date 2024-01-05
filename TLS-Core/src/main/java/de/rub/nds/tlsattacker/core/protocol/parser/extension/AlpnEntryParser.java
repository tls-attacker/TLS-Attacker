/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.extension.alpn.AlpnEntry;
import java.io.InputStream;

public class AlpnEntryParser extends Parser<AlpnEntry> {

    public AlpnEntryParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(AlpnEntry entry) {
        entry.setAlpnEntryLength(parseIntField(ExtensionByteLength.ALPN_ENTRY_LENGTH));
        entry.setAlpnEntry(new String(parseByteArrayField(entry.getAlpnEntryLength().getValue())));
        entry.setAlpnEntryConfig(entry.getAlpnEntry().getValue());
    }
}
