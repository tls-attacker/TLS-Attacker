/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.supplementaldata;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.supplementaldata.SupplementalDataEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SupplementalDataEntryParser extends Parser<SupplementalDataEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SupplementalDataEntryParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public SupplementalDataEntry parse() {
        LOGGER.debug("Parsing SupplementalDataEntry");
        SupplementalDataEntry entry = new SupplementalDataEntry();
        parseSupplementalDataEntryType(entry);
        parseSupplementalDataEntryLength(entry);
        parseSupplementalDataEntry(entry);
        return entry;
    }

    private void parseSupplementalDataEntryType(SupplementalDataEntry entry) {
        entry.setSupplementalDataEntryType(parseIntField(HandshakeByteLength.SUPPLEMENTAL_DATA_ENTRY_TYPE_LENGTH));
        LOGGER.debug("SupplementalDataEntryType: " + entry.getSupplementalDataEntryType().getValue());
    }

    private void parseSupplementalDataEntryLength(SupplementalDataEntry entry) {
        entry.setSupplementalDataEntryLength(parseIntField(HandshakeByteLength.SUPPLEMENTAL_DATA_ENTRY_LENGTH));
        LOGGER.debug("SupplementalDataEntryLength: " + entry.getSupplementalDataEntryLength().getValue());
    }

    private void parseSupplementalDataEntry(SupplementalDataEntry entry) {
        entry.setSupplementalDataEntry(parseByteArrayField(entry.getSupplementalDataEntryLength().getValue()));
        LOGGER.debug("SupplementalDataEntry: "
                + ArrayConverter.bytesToHexString(entry.getSupplementalDataEntry().getValue()));
    }

}
