/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BlobRecordSerializer extends AbstractRecordSerializer<BlobRecord> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final BlobRecord record;

    public BlobRecordSerializer(BlobRecord record) {
        this.record = record;
    }

    @Override
    protected byte[] serializeBytes() {
        LOGGER.debug("Serializing BlobRecord");
        writeProtocolMessageBytes(record);
        return getAlreadySerialized();
    }

    private void writeProtocolMessageBytes(BlobRecord record) {
        appendBytes(record.getProtocolMessageBytes().getValue());
        LOGGER.debug("ProtocolMessageBytes: "
                + ArrayConverter.bytesToHexString(record.getProtocolMessageBytes().getValue()));
    }
}
