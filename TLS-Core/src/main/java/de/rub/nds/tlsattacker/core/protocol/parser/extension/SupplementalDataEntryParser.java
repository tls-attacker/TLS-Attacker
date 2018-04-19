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
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupplementalData.SupplementalDataEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;

public class SupplementalDataEntryParser extends Parser<SupplementalDataEntry> {
    
    public SupplementalDataEntryParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public SupplementalDataEntry parse() {
        int supplementalDataEntryType = parseIntField(ExtensionByteLength.SUPPLEMENTAL_DATA_ENTRY_TYPE_LENGTH);
        int supplementalDataEntryLength = parseIntField(ExtensionByteLength.SUPPLEMENTAL_DATA_ENTRY_LENGTH);
        byte[] supplementalDataEntryBytes = parseByteArrayField(supplementalDataEntryLength);
        SupplementalDataEntry entry = new SupplementalDataEntry(supplementalDataEntryType, supplementalDataEntryLength, 
                supplementalDataEntryBytes);
        return entry;
    }
    
}
