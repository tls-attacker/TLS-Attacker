/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.SupplementalDataMessage;
import de.rub.nds.tlsattacker.core.protocol.message.supplementaldata.SupplementalDataEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.supplementaldata.SupplementalDataEntryParser;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SupplementalDataParser extends HandshakeMessageParser<SupplementalDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param tlsContext
     */
    public SupplementalDataParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(SupplementalDataMessage msg) {
        LOGGER.debug("Parsing SupplementalDataMessage");
        parseSupplementalDataLength(msg);
        parseSupplementalDataBytes(msg);
        parseSupplementalDataEntries(msg);
    }

    private void parseSupplementalDataLength(SupplementalDataMessage msg) {
        msg.setSupplementalDataLength(parseIntField(HandshakeByteLength.SUPPLEMENTAL_DATA_LENGTH));
        LOGGER.debug("SupplementalDataLength: " + msg.getSupplementalDataLength().getValue());
    }

    private void parseSupplementalDataBytes(SupplementalDataMessage msg) {
        msg.setSupplementalDataBytes(
                parseByteArrayField(msg.getSupplementalDataLength().getValue()));
        LOGGER.debug("SupplementalDataBytes: {}", msg.getSupplementalDataBytes().getValue());
    }

    private void parseSupplementalDataEntries(SupplementalDataMessage msg) {
        List<SupplementalDataEntry> entryList = new LinkedList<>();
        ByteArrayInputStream innerStream =
                new ByteArrayInputStream(msg.getSupplementalDataBytes().getValue());
        while (innerStream.available() > 0) {
            SupplementalDataEntryParser parser = new SupplementalDataEntryParser(innerStream);
            SupplementalDataEntry entry = new SupplementalDataEntry();
            parser.parse(entry);
            entryList.add(entry);
        }
        msg.setEntries(entryList);
    }
}
