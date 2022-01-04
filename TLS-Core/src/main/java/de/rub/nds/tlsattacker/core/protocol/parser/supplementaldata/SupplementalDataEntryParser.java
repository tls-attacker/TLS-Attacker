/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.supplementaldata;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.supplementaldata.SupplementalDataEntry;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

public class SupplementalDataEntryParser extends Parser<SupplementalDataEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SupplementalDataEntryParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(SupplementalDataEntry entry) {
        LOGGER.debug("Parsing SupplementalDataEntry");
        parseSupplementalDataEntryType(entry);
        parseSupplementalDataEntryLength(entry);
        parseSupplementalDataEntry(entry);
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
        LOGGER.debug(
                "SupplementalDataEntry: " + ArrayConverter.bytesToHexString(entry.getSupplementalDataEntry().getValue()));
    }

}
