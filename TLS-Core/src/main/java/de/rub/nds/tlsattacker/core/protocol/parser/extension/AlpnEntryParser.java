/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.alpn.AlpnEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;

public class AlpnEntryParser extends Parser<AlpnEntry> {

    public AlpnEntryParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public AlpnEntry parse() {
        AlpnEntry entry = new AlpnEntry();
        entry.setAlpnEntryLength(parseIntField(ExtensionByteLength.ALPN_ENTRY_LENGTH));
        entry.setAlpnEntryBytes(parseByteArrayField(entry.getAlpnEntryLength().getValue()));
        entry.setAlpnEntryConfig(entry.getAlpnEntryBytes().getValue());
        return entry;
    }

}
