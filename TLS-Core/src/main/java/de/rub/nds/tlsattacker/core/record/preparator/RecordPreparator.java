/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The cleanRecordBytes should be set when the record preparator received the record
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
        compressor.compress(record);
        encrypt();
    }

    @Override
    public void encrypt() {
        LOGGER.debug("Encrypting Record");
        if (chooser.getSelectedProtocolVersion().isTLS13()
            && record.getContentMessageType() == ProtocolMessageType.CHANGE_CIPHER_SPEC
            && !chooser.getConfig().isEncryptChangeCipherSpec()) {
            // The CCS message in TLS 1.3 is an exception that does not get
            // encrypted
            record.prepareComputations();
            record.setProtocolMessageBytes(record.getCleanProtocolMessageBytes().getValue());
        } else {
            encryptor.encrypt(record);
        }
        prepareLength(record);
    }

    private void prepareContentType(Record record) {
        record.setContentType(type.getValue());
        prepareContentMessageType(type);
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

    private void prepareLength(Record record) {
        record.setLength(record.getProtocolMessageBytes().getValue().length);
        LOGGER.debug("Length: " + record.getLength().getValue());
    }
}
