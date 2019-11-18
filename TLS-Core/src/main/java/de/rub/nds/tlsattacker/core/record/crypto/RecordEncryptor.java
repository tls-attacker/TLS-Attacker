/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.EncryptionRequest;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordEncryptor extends Encryptor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext context;

    public RecordEncryptor(RecordCipher recordCipher, TlsContext context) {
        super(recordCipher);
        this.context = context;
    }

    @Override
    public void encrypt(BlobRecord record) {
        LOGGER.debug("Encrypting BlobRecord");
        byte[] encrypted = recordCipher.encrypt(
                getEncryptionRequest(record.getCleanProtocolMessageBytes().getValue(), null))
                .getCompleteEncryptedCipherText();
        record.setProtocolMessageBytes(encrypted);
        LOGGER.debug("ProtocolMessageBytes: "
                + ArrayConverter.bytesToHexString(record.getProtocolMessageBytes().getValue()));
    }

    @Override
    public void encrypt(Record record) {

        LOGGER.debug("Encrypting Record:");
        CipherSuite cipherSuite = context.getChooser().getSelectedCipherSuite();
        // initialising mac
        record.getComputations().setMac(new byte[0]);
        byte[] cleanBytes = record.getCleanProtocolMessageBytes().getValue();

        record.getComputations().setNonMetaDataMaced(cleanBytes);
        if (context.getChooser().getSelectedProtocolVersion().isTLS13()) {
            // TLS13 needs the record length before encrypting
            // Encrypted length
            int cleanLength = record.getCleanProtocolMessageBytes().getValue().length;
            int length = cleanLength + recordCipher.getTagSize() + 1; // +1 for
                                                                      // the
                                                                      // encrypted
                                                                      // record
                                                                      // type
            record.setLength(length);
        }
        byte[] additionalAuthenticatedData = collectAdditionalAuthenticatedData(record, context.getChooser()
                .getSelectedProtocolVersion());
        record.getComputations().setAuthenticatedMetaData(additionalAuthenticatedData);
        if (!isEncryptThenMac(cipherSuite) && cipherSuite.isUsingMac()) {
            LOGGER.debug("EncryptThenMac Extension is not active");

            byte[] mac = recordCipher.calculateMac(ArrayConverter.concatenate(record.getComputations()
                    .getAuthenticatedMetaData().getValue(), record.getComputations().getNonMetaDataMaced().getValue()),
                    context.getChooser().getConnectionEndType());
            setMac(record, mac);
        }

        setUnpaddedRecordBytes(record, cleanBytes);

        byte[] padding;

        if (context.getChooser().getSelectedProtocolVersion().isTLS13()
                || context.getActiveKeySetTypeWrite() == Tls13KeySetType.EARLY_TRAFFIC_SECRETS) {
            padding = recordCipher.calculatePadding(record.getComputations().getPaddingLength().getValue());
        } else {
            int paddingLength = recordCipher.calculatePaddingLength(record.getComputations().getUnpaddedRecordBytes()
                    .getValue().length);
            record.getComputations().setPaddingLength(paddingLength);
            padding = recordCipher.calculatePadding(record.getComputations().getPaddingLength().getValue());
        }
        setPadding(record, padding);
        setPaddingLength(record);
        byte[] plain;
        if ((context.getChooser().getSelectedProtocolVersion().isTLS13() || context.getActiveKeySetTypeWrite() == Tls13KeySetType.EARLY_TRAFFIC_SECRETS)
                && context.getActiveKeySetTypeWrite() != Tls13KeySetType.NONE) {
            plain = ArrayConverter.concatenate(record.getComputations().getUnpaddedRecordBytes().getValue(), record
                    .getContentMessageType().getArrayValue(), record.getComputations().getPadding().getValue());
        } else {
            plain = ArrayConverter.concatenate(record.getComputations().getUnpaddedRecordBytes().getValue(), record
                    .getComputations().getPadding().getValue());
        }
        setPlainRecordBytes(record, plain);
        byte[] encrypted = recordCipher.encrypt(
                getEncryptionRequest(record.getComputations().getPlainRecordBytes().getValue(), record
                        .getComputations().getAuthenticatedMetaData().getValue())).getCompleteEncryptedCipherText();
        if (isEncryptThenMac(cipherSuite)) {
            LOGGER.debug("EncryptThenMac Extension active");
            record.getComputations().setNonMetaDataMaced(encrypted);
            additionalAuthenticatedData = collectAdditionalAuthenticatedData(record, context.getChooser()
                    .getSelectedProtocolVersion());
            record.getComputations().setAuthenticatedMetaData(additionalAuthenticatedData);
            byte[] mac = recordCipher.calculateMac(ArrayConverter.concatenate(record.getComputations()
                    .getAuthenticatedMetaData().getValue(), encrypted), context.getChooser().getConnectionEndType());
            setMac(record, mac);
            encrypted = ArrayConverter.concatenate(encrypted, record.getComputations().getMac().getValue());
        }
        setProtocolMessageBytes(record, encrypted);
        context.increaseWriteSequenceNumber();
    }

    private boolean isEncryptThenMac(CipherSuite cipherSuite) {
        return context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC) && cipherSuite.isCBC()
                && recordCipher.isUsingMac();
    }

    private void setMac(Record record, byte[] mac) {
        record.getComputations().setMac(mac);
        LOGGER.debug("MAC: " + ArrayConverter.bytesToHexString(record.getComputations().getMac().getValue()));
    }

    private void setUnpaddedRecordBytes(Record record, byte[] cleanBytes) {
        record.getComputations().setUnpaddedRecordBytes(
                ArrayConverter.concatenate(cleanBytes, record.getComputations().getMac().getValue()));
        LOGGER.debug("UnpaddedRecordBytes: "
                + ArrayConverter.bytesToHexString(record.getComputations().getUnpaddedRecordBytes().getValue()));
    }

    private void setPadding(Record record, byte[] padding) {
        record.getComputations().setPadding(padding);
        LOGGER.debug("Padding: " + ArrayConverter.bytesToHexString(record.getComputations().getPadding().getValue()));
    }

    private void setPaddingLength(Record record) {
        record.getComputations().setPaddingLength(record.getComputations().getPadding().getValue().length);
        LOGGER.debug("PaddingLength: " + record.getComputations().getPaddingLength().getValue());
    }

    private void setPlainRecordBytes(Record record, byte[] plain) {
        record.getComputations().setPlainRecordBytes(plain);
        LOGGER.debug("PlainRecordBytes: "
                + ArrayConverter.bytesToHexString(record.getComputations().getPlainRecordBytes().getValue()));
    }

    private void setProtocolMessageBytes(Record record, byte[] encrypted) {
        record.setProtocolMessageBytes(encrypted);
        LOGGER.debug("ProtocolMessageBytes: "
                + ArrayConverter.bytesToHexString(record.getProtocolMessageBytes().getValue()));
    }

    private EncryptionRequest getEncryptionRequest(byte[] data, byte[] additionalAuthenticatedData) {
        return new EncryptionRequest(data, recordCipher.getEncryptionIV(), additionalAuthenticatedData);
    }
}
