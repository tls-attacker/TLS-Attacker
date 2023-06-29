/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.supplementaldata;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.supplementaldata.SupplementalDataEntry;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
        entry.setSupplementalDataEntryType(
                parseIntField(HandshakeByteLength.SUPPLEMENTAL_DATA_ENTRY_TYPE_LENGTH));
        LOGGER.debug(
                "SupplementalDataEntryType: " + entry.getSupplementalDataEntryType().getValue());
    }

    private void parseSupplementalDataEntryLength(SupplementalDataEntry entry) {
        entry.setSupplementalDataEntryLength(
                parseIntField(HandshakeByteLength.SUPPLEMENTAL_DATA_ENTRY_LENGTH));
        LOGGER.debug(
                "SupplementalDataEntryLength: "
                        + entry.getSupplementalDataEntryLength().getValue());
    }

    private void parseSupplementalDataEntry(SupplementalDataEntry entry) {
        entry.setSupplementalDataEntry(
                parseByteArrayField(entry.getSupplementalDataEntryLength().getValue()));
        LOGGER.debug("SupplementalDataEntry: {}", entry.getSupplementalDataEntry().getValue());
    }
}
