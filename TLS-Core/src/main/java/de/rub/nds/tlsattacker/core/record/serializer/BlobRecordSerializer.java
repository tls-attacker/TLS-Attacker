/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.serializer;

import de.rub.nds.tlsattacker.core.record.BlobRecord;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class BlobRecordSerializer extends AbstractRecordSerializer<BlobRecord> {

    private final BlobRecord record;

    public BlobRecordSerializer(BlobRecord record) {
        this.record = record;
    }

    @Override
    protected byte[] serializeBytes() {
        appendBytes(record.getProtocolMessageBytes().getValue());
        return getAlreadySerialized();
    }
}
