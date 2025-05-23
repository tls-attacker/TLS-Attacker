/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.preparator;

import de.rub.nds.tlsattacker.core.constants.Dtls13UnifiedHeaderBits;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.impl.RecordLayer;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordNullCipher;
import de.rub.nds.tlsattacker.core.record.compressor.RecordCompressor;
import de.rub.nds.tlsattacker.core.record.crypto.Encryptor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** The cleanRecordBytes should be set when the record preparator received the record */
public class RecordPreparator extends Preparator<Record> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Record record;
    private final Encryptor encryptor;
    private final TlsContext tlsContext;
    private final RecordCompressor compressor;

    private ProtocolMessageType type;

    public RecordPreparator(
            TlsContext tlsContext,
            Record record,
            Encryptor encryptor,
            ProtocolMessageType type,
            RecordCompressor compressor) {
        super(tlsContext.getChooser(), record);
        this.record = record;
        this.encryptor = encryptor;
        this.tlsContext = tlsContext;
        this.compressor = compressor;
        this.type = type;
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing Record");
        prepareConnectionId(record);
        record.prepareComputations();
        prepareContentType(record);
        prepareProtocolVersion(record);
        // Set DTLS 1.3 unified header only in to be encrypted records
        if (tlsContext.getChooser().getSelectedProtocolVersion().isDTLS13()
                && !(encryptor.getRecordCipher(record.getEpoch().getValue())
                        instanceof RecordNullCipher)) {
            prepareDtls13UnifiedHeader(record);
        }
        compressor.compress(record);
        encrypt();
    }

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

    private void prepareConnectionId(Record record) {
        if (chooser.getSelectedProtocolVersion().isDTLS()) {
            RecordLayer recordLayer = tlsContext.getRecordLayer();
            byte[] connectionId =
                    recordLayer
                            .getEncryptor()
                            .getRecordCipher(recordLayer.getWriteEpoch())
                            .getState()
                            .getConnectionId();
            if (connectionId != null
                    && tlsContext.isExtensionNegotiated(ExtensionType.CONNECTION_ID)) {
                record.setConnectionId(connectionId);
                LOGGER.debug("ConnectionId: {}", record.getConnectionId().getValue());
            }
        }
    }

    private void prepareContentType(Record record) {
        record.setContentType(type.getValue());
        LOGGER.debug("ContentType: {}", type.getValue());
        prepareContentMessageType(type);
    }

    private void prepareProtocolVersion(Record record) {
        if (chooser.getSelectedProtocolVersion().isTLS13()
                || tlsContext.getActiveKeySetTypeWrite() == Tls13KeySetType.EARLY_TRAFFIC_SECRETS) {
            record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        } else if (chooser.getSelectedProtocolVersion().isDTLS13()) {
            record.setProtocolVersion(ProtocolVersion.DTLS12.getValue());
        } else {
            record.setProtocolVersion(chooser.getSelectedProtocolVersion().getValue());
        }
        LOGGER.debug("ProtocolVersion: {}", record.getProtocolVersion().getValue());
    }

    private void prepareLength(Record record) {
        record.setLength(record.getProtocolMessageBytes().getValue().length);
        LOGGER.debug("Length: {}", record.getLength().getValue());
    }

    protected void prepareContentMessageType(ProtocolMessageType type) {
        getObject().setContentMessageType(this.type);
        LOGGER.debug("ContentMessageType: {}", type.getArrayValue());
    }

    protected void prepareDtls13UnifiedHeader(Record record) {
        record.setUnifiedHeader(createDtls13UnifiedHeader(record, tlsContext));
        LOGGER.debug(
                "UnifiedHeader: 00{}",
                Integer.toBinaryString(record.getUnifiedHeader().getValue()));
    }

    private byte createDtls13UnifiedHeader(Record record, TlsContext context) {
        byte header = Dtls13UnifiedHeaderBits.HEADER_BASE;
        // Setting the flag for connection id
        if (record.getConnectionId() != null
                && record.getConnectionId().getValue() != null
                && record.getConnectionId().getValue().length > 0) {
            header ^= Dtls13UnifiedHeaderBits.CID_PRESENT;
        }
        // Setting the flag for sequence number
        if (context.getConfig().getUseDtls13HeaderSeqNumSizeLongEncoding()) {
            header ^= Dtls13UnifiedHeaderBits.SQN_LONG;
        }
        // Setting the flag for length
        header ^= Dtls13UnifiedHeaderBits.LENGTH_PRESENT;
        // Setting the epoch bits
        byte lowerEpoch = (byte) (record.getEpoch().getValue() % 4);
        header ^= lowerEpoch;
        return header;
    }
}
