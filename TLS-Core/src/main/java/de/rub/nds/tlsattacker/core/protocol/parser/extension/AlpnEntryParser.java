/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.alpn.AlpnEntry;
import de.rub.nds.tlsattacker.core.protocol.Parser;

public class AlpnEntryParser extends Parser<AlpnEntry> {

    public AlpnEntryParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public AlpnEntry parse() {
        AlpnEntry entry = new AlpnEntry();
        entry.setAlpnEntryLength(parseIntField(ExtensionByteLength.ALPN_ENTRY_LENGTH));
        entry.setAlpnEntry(new String(parseByteArrayField(entry.getAlpnEntryLength().getValue())));
        entry.setAlpnEntryConfig(entry.getAlpnEntry().getValue());
        return entry;
    }

}
