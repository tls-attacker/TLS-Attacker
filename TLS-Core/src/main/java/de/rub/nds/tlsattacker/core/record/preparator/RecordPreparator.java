/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.crypto.Encryptor;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.math.BigInteger;

/**
 * The cleanrecordbytes should be set when the record preparator received the
 * record
 *
 * @author Robert Merget <robert.merget@rub.de>
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
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
        LOGGER.debug("Preparing Record");
        prepareContentType(record);
        prepareProtocolVersion(record);
        prepareSequenceNumber(record);
        if (context.getSelectedProtocolVersion() == ProtocolVersion.TLS13) {
            record.setPaddingLength(context.getConfig().getPaddingLength());
        }
        encryptor.encrypt(record);
        prepareLength(record);
    }

    private void prepareContentType(Record record) {
        if (context.getSelectedProtocolVersion() == ProtocolVersion.TLS13 && context.isEncryptActive() == true) {
            record.setContentType(ProtocolMessageType.APPLICATION_DATA.getValue());
        } else {
            record.setContentType(type.getValue());
        }
        prepareConentMessageType(type);
        LOGGER.debug("ContentType: " + type.getValue());
    }

    private void prepareProtocolVersion(Record record) {
        if (context.getSelectedProtocolVersion() != ProtocolVersion.TLS13) {
            record.setProtocolVersion(context.getSelectedProtocolVersion().getValue());
        } else {
            record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        }
        LOGGER.debug("ProtocolVersion: " + ArrayConverter.bytesToHexString(record.getProtocolVersion().getValue()));
    }

    private void prepareSequenceNumber(Record record) {
        record.setSequenceNumber(BigInteger.valueOf(context.getSequenceNumber()));
        LOGGER.debug("SequenceNumber: " + record.getSequenceNumber().getValue());
    }

    private void prepareLength(Record record) {
        record.setLength(record.getProtocolMessageBytes().getValue().length);
        LOGGER.debug("Length: " + record.getLength().getValue());
    }
    
    private void preparePaddingLength(Record record) {
        record.setPaddingLength(context.getConfig().getPaddingLength());
        LOGGER.debug("PaddingLength: " + record.getPaddingLength().getValue());
    }
}
