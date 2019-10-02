/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.protocol.message.SupplementalDataMessage;
import de.rub.nds.tlsattacker.core.protocol.message.supplementaldata.SupplementalDataEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.supplementaldata.SupplementalDataEntryParser;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SupplementalDataParser extends HandshakeMessageParser<SupplementalDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param pointer
     *            Position in the array where the HandshakeMessageParser is
     *            supposed to start parsing
     * @param array
     *            The byte[] which the HandshakeMessageParser is supposed to
     *            parse
     * @param version
     *            The Version for which this message should be parsed
     */
    public SupplementalDataParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, HandshakeMessageType.SUPPLEMENTAL_DATA, version);
    }

    @Override
    protected void parseHandshakeMessageContent(SupplementalDataMessage msg) {
        LOGGER.debug("Parsing SupplementalDataMessage");
        parseSupplementalDataLength(msg);
        parseSupplementalDataBytes(msg);
        parseSupplementalDataEntries(msg);
    }

    @Override
    protected SupplementalDataMessage createHandshakeMessage() {
        return new SupplementalDataMessage();
    }

    private void parseSupplementalDataLength(SupplementalDataMessage msg) {
        msg.setSupplementalDataLength(parseIntField(HandshakeByteLength.SUPPLEMENTAL_DATA_LENGTH));
        LOGGER.debug("SupplementalDataLength: " + msg.getSupplementalDataLength().getValue());
    }

    private void parseSupplementalDataBytes(SupplementalDataMessage msg) {
        msg.setSupplementalDataBytes(parseByteArrayField(msg.getSupplementalDataLength().getValue()));
        LOGGER.debug("SupplementalDataBytes: "
                + ArrayConverter.bytesToHexString(msg.getSupplementalDataBytes().getValue()));
    }

    private void parseSupplementalDataEntries(SupplementalDataMessage msg) {
        int pointer = 0;
        List<SupplementalDataEntry> entryList = new LinkedList<>();
        while (pointer < msg.getSupplementalDataLength().getValue()) {
            SupplementalDataEntryParser parser = new SupplementalDataEntryParser(pointer, msg
                    .getSupplementalDataBytes().getValue());
            entryList.add(parser.parse());
            if (pointer == parser.getPointer()) {
                throw new ParserException("Ran into infinite Loop while parsing SupplementalDataEntries");
            }
            pointer = parser.getPointer();
        }
        msg.setEntries(entryList);
    }
}
