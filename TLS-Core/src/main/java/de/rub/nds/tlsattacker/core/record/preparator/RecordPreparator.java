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
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.compressor.RecordCompressor;
import de.rub.nds.tlsattacker.core.record.crypto.Encryptor;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The cleanrecordbytes should be set when the record preparator received the
 * record
 */
public class RecordPreparator extends AbstractRecordPreparator<Record> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Record record;
    private final Encryptor encryptor;
    private final RecordCompressor compressor;

    public RecordPreparator(Chooser chooser, Record record, Encryptor encryptor, ProtocolMessageType type,
            RecordCompressor compressor) {
        super(chooser, record, type);
        this.record = record;
        this.encryptor = encryptor;
        this.compressor = compressor;

    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing Record");
        record.prepareComputations();
        prepareContentType(record);
        prepareProtocolVersion(record);
        prepareSequenceNumber(record);
        if (chooser.getSelectedProtocolVersion().isTLS13()
                || chooser.getContext().getActiveKeySetTypeWrite() == Tls13KeySetType.EARLY_TRAFFIC_SECRETS) {
            preparePaddingLength(record);
        }

        if (isDTLS()) {
            prepareEpoch(record);
            prepareDtlsSequenceNumber(record);
        }

        compressor.compress(record);

        encryptor.encrypt(record);
        prepareLength(record);
    }

    private void prepareContentType(Record record) {
        if ((chooser.getSelectedProtocolVersion().isTLS13() || chooser.getContext().getActiveKeySetTypeWrite() == Tls13KeySetType.EARLY_TRAFFIC_SECRETS)
                && chooser.getContext().getActiveKeySetTypeWrite() != Tls13KeySetType.NONE) {
            record.setContentType(ProtocolMessageType.APPLICATION_DATA.getValue());
        } else {
            record.setContentType(type.getValue());
        }
        prepareConentMessageType(type);
        LOGGER.debug("ContentType: " + type.getValue());
    }

    private void prepareProtocolVersion(Record record) {
        if (chooser.getSelectedProtocolVersion().isTLS13()
                || chooser.getContext().getActiveKeySetTypeWrite() == Tls13KeySetType.EARLY_TRAFFIC_SECRETS) {
            record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        } else {
            record.setProtocolVersion(chooser.getSelectedProtocolVersion().getValue());
        }
        LOGGER.debug("ProtocolVersion: " + ArrayConverter.bytesToHexString(record.getProtocolVersion().getValue()));
    }

    private boolean isDTLS() {
        return chooser.getSelectedProtocolVersion().isDTLS();
    }

    private void prepareEpoch(Record record) {
        record.setEpoch(chooser.getContext().getDtlsSendEpoch());
        LOGGER.debug("Epoch: " + record.getEpoch().getValue());
    }

    private void prepareDtlsSequenceNumber(Record record) {
        // the dtls sequence number takes is updated in the same way as the
        // implicit sequence number in TLS
        record.setSequenceNumber(record.getComputations().getSequenceNumber().getValue());

        LOGGER.debug("DtlsSequenceNumber: " + record.getSequenceNumber().getValue());
    }

    private void prepareSequenceNumber(Record record) {
        record.getComputations().setSequenceNumber(BigInteger.valueOf(chooser.getContext().getWriteSequenceNumber()));
        LOGGER.debug("SequenceNumber: " + record.getComputations().getSequenceNumber().getValue());
    }

    private void prepareLength(Record record) {
        record.setLength(record.getProtocolMessageBytes().getValue().length);
        LOGGER.debug("Length: " + record.getLength().getValue());
    }

    private void preparePaddingLength(Record record) {
        record.getComputations().setPaddingLength(chooser.getConfig().getPaddingLength());
        LOGGER.debug("PaddingLength: " + record.getComputations().getPaddingLength().getValue());
    }
}
