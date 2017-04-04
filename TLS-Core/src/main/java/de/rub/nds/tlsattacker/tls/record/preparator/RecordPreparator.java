/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.record.preparator;

import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.tls.record.encryptor.Encryptor;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 * The cleanrecordbytes should be set when the record preparator received the
 * record
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class RecordPreparator extends AbstractRecordPreparator<Record> {

    private final Record record;
    private final Encryptor encryptor;

    public RecordPreparator(TlsContext context, Record record, Encryptor encryptor, ProtocolMessageType type) {
        super(context, record, type);
        this.record = record;
        this.encryptor = encryptor;
    }

    @Override
    public void prepare() {
        record.setContentType(type.getValue());
        record.setProtocolVersion(context.getSelectedProtocolVersion().getValue());
        encryptor.encrypt(record);
        record.setLength(record.getProtocolMessageBytes().getValue().length);
    }
}