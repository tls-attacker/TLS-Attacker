/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.record;

import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.record.encryptor.Encryptor;
import de.rub.nds.tlsattacker.tls.record.parser.AbstractRecordParser;
import de.rub.nds.tlsattacker.tls.record.parser.BlobRecordParser;
import de.rub.nds.tlsattacker.tls.record.preparator.AbstractRecordPreparator;
import de.rub.nds.tlsattacker.tls.record.preparator.BlobRecordPreparator;
import de.rub.nds.tlsattacker.tls.record.serializer.AbstractRecordSerializer;
import de.rub.nds.tlsattacker.tls.record.serializer.BlobRecordSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 * A Blob Record is not a record in a conventional sense but is rather a non
 * exisiting record and represents just a collection of bytes. Is used for
 * unparseable Records and for SSLv2
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class BlobRecord extends AbstractRecord {

    public BlobRecord() {
        setMaxRecordLengthConfig(Integer.MAX_VALUE);
    }

    public BlobRecord(TlsConfig config) {
        super(config);
        setMaxRecordLengthConfig(Integer.MAX_VALUE);
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
