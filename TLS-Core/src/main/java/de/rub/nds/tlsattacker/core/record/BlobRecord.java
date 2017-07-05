/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.crypto.Encryptor;
import de.rub.nds.tlsattacker.core.record.parser.AbstractRecordParser;
import de.rub.nds.tlsattacker.core.record.parser.BlobRecordParser;
import de.rub.nds.tlsattacker.core.record.preparator.AbstractRecordPreparator;
import de.rub.nds.tlsattacker.core.record.preparator.BlobRecordPreparator;
import de.rub.nds.tlsattacker.core.record.serializer.AbstractRecordSerializer;
import de.rub.nds.tlsattacker.core.record.serializer.BlobRecordSerializer;
import de.rub.nds.tlsattacker.core.config.TlsConfig;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 * A Blob Record is not a record in a conventional sense but is rather a non
 * exisiting record and represents just a collection of bytes. Is used for
 * unparseable Records and for SSLv2
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class BlobRecord extends AbstractRecord {

    public BlobRecord() {
    }

    public BlobRecord(TlsConfig config) {
        super(config);
    }

    @Override
    public AbstractRecordPreparator getRecordPreparator(TlsContext context, Encryptor encryptor,
            ProtocolMessageType type) {
        return new BlobRecordPreparator(context, this, encryptor, type);
    }

    @Override
    public AbstractRecordParser getRecordParser(int startposition, byte[] array, ProtocolVersion version) {
        return new BlobRecordParser(startposition, array, version);
    }

    @Override
    public AbstractRecordSerializer getRecordSerializer() {
        return new BlobRecordSerializer(this);
    }

}
