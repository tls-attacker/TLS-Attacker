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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.SupplementalDataMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupplementalData.SupplementalDataEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SupplementalDataEntryParser;
import java.util.LinkedList;
import java.util.List;

/**
 * TODO
 */
public class SupplementalDataParser extends HandshakeMessageParser<SupplementalDataMessage> {

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
        byte[] supplementalDataBytes = parseByteArrayField(msg.getSupplementalDataLength().getValue());
        msg.setSupplementalDataBytes(supplementalDataBytes);
        LOGGER.debug("SupplementalDataBytes: " + ArrayConverter.bytesToHexString(msg.getSupplementalDataBytes().getValue()));
        List<SupplementalDataEntry> entryList = new LinkedList<>();
        int pointer = 0;
        while (pointer < supplementalDataBytes.length) {
            SupplementalDataEntryParser parser = new SupplementalDataEntryParser(pointer, supplementalDataBytes);
            entryList.add(parser.parse());
            pointer = parser.getPointer();
        }
        msg.setEntries(entryList);
    }
}
