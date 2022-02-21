/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.SupplementalDataMessage;
import de.rub.nds.tlsattacker.core.protocol.message.supplementaldata.SupplementalDataEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.supplementaldata.SupplementalDataEntryParser;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

public class SupplementalDataParser extends HandshakeMessageParser<SupplementalDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param version
     *                   The Version for which this message should be parsed
     * @param tlsContext
     */
    public SupplementalDataParser(InputStream stream, ProtocolVersion version, TlsContext tlsContext) {
        super(stream, version, tlsContext);
    }

    @Override
    protected void parseHandshakeMessageContent(SupplementalDataMessage msg) {
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
        msg.setSupplementalDataBytes(parseByteArrayField(msg.getSupplementalDataLength().getValue()));
        LOGGER.debug(
            "SupplementalDataBytes: " + ArrayConverter.bytesToHexString(msg.getSupplementalDataBytes().getValue()));
    }

    private void parseSupplementalDataEntries(SupplementalDataMessage msg) {
        List<SupplementalDataEntry> entryList = new LinkedList<>();
        ByteArrayInputStream innerStream = new ByteArrayInputStream(msg.getSupplementalDataBytes().getValue());
        while (innerStream.available() > 0) {
            SupplementalDataEntryParser parser = new SupplementalDataEntryParser(innerStream);
            SupplementalDataEntry entry = new SupplementalDataEntry();
            parser.parse(entry);
            entryList.add(entry);
        }
        msg.setEntries(entryList);
    }
}
