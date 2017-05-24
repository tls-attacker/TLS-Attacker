/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.preparator;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.crypto.Encryptor;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

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
        if (context.getSelectedProtocolVersion() != ProtocolVersion.TLS13) {
            record.setContentType(type.getValue());
            prepareConentMessageType(type);
            record.setProtocolVersion(context.getSelectedProtocolVersion().getValue());
        } else {
            if (context.isEncryptActive() == true) {
                record.setContentType(ProtocolMessageType.APPLICATION_DATA.getValue());
                prepareConentMessageType(type);
            } else {
                record.setContentType(type.getValue());
                prepareConentMessageType(type);
            }
            record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
            record.setPaddingLength(context.getConfig().getPaddingLength());
        }
        encryptor.encrypt(record);
        record.setLength(record.getProtocolMessageBytes().getValue().length);
    }
}
