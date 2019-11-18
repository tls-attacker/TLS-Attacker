/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BlobRecordParser extends AbstractRecordParser<BlobRecord> {

    private static final Logger LOGGER = LogManager.getLogger();

    public BlobRecordParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array, version);
    }

    @Override
    public BlobRecord parse() {
        LOGGER.debug("Parsing BlobRecord");
        BlobRecord record = new BlobRecord();
        record.setContentMessageType(ProtocolMessageType.UNKNOWN);
        parseProtocolMessageBytes(record);
        record.setCompleteRecordBytes(getAlreadyParsed());
        return record;
    }

    private void parseProtocolMessageBytes(BlobRecord record) {
        record.setProtocolMessageBytes(parseByteArrayField(getBytesLeft()));
        LOGGER.debug("ProtocolMessageBytes: "
                + ArrayConverter.bytesToHexString(record.getProtocolMessageBytes().getValue()));
    }
}
