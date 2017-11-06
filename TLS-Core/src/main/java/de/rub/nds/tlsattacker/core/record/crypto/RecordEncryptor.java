/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.EncryptionRequest;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**


 */
public class RecordEncryptor extends Encryptor {

    private final TlsContext context;

    public RecordEncryptor(RecordCipher recordCipher, TlsContext context) {
        super(recordCipher);
        this.context = context;
    }

    @Override
    public void encrypt(BlobRecord record) {
        LOGGER.debug("Encrypting BlobRecord");
        byte[] encrypted = recordCipher.encrypt(getEncryptionRequest(record.getCleanProtocolMessageBytes().getValue()))
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
        record.setMac(new byte[0]);
        byte[] cleanBytes = record.getCleanProtocolMessageBytes().getValue();

        if (!isEncryptThenMac(cipherSuite)) {
            LOGGER.trace("EncryptThenMac is not active");
            record.setNonMetaDataMaced(cleanBytes);
            byte[] additionalAuthenticatedData = collectAdditionalAuthenticatedData(record, context.getChooser()
                    .getSelectedProtocolVersion());
            record.setAuthenticatedMetaData(additionalAuthenticatedData);
            recordCipher.setAdditionalAuthenticatedData(record.getAuthenticatedMetaData().getValue());
            if (cipherSuite.isUsingMac()) {
                byte[] mac = recordCipher.calculateMac(ArrayConverter.concatenate(record.getAuthenticatedMetaData()
                        .getValue(), record.getNonMetaDataMaced().getValue()));
                setMac(record, mac);
            }
        }
        setUnpaddedRecordBytes(record, cleanBytes);

        byte[] padding;
        if (context.getChooser().getSelectedProtocolVersion().isTLS13()) {
            padding = recordCipher.calculatePadding(record.getPaddingLength().getValue());
        } else {
            int paddingLength = recordCipher.calculatePaddingLength(record.getUnpaddedRecordBytes().getValue().length);
            record.setPaddingLength(paddingLength);
            padding = recordCipher.calculatePadding(record.getPaddingLength().getValue());
        }
        setPadding(record, padding);
        setPaddingLength(record);
        byte[] plain;
        if (context.getChooser().getSelectedProtocolVersion().isTLS13() && context.isEncryptActive()) {
            plain = ArrayConverter.concatenate(record.getUnpaddedRecordBytes().getValue(), record
                    .getContentMessageType().getArrayValue(), record.getPadding().getValue());
        } else {
            plain = ArrayConverter.concatenate(record.getUnpaddedRecordBytes().getValue(), record.getPadding()
                    .getValue());
        }
        setPlainRecordBytes(record, plain);
        byte[] encrypted = recordCipher.encrypt(getEncryptionRequest(record.getPlainRecordBytes().getValue()))
                .getCompleteEncryptedCipherText();
        if (isEncryptThenMac(cipherSuite)) {
            LOGGER.debug("EncryptThenMac Extension active");
            record.setNonMetaDataMaced(encrypted);
            byte[] additionalAuthenticatedData = collectAdditionalAuthenticatedData(record, context.getChooser()
                    .getSelectedProtocolVersion());
            record.setAuthenticatedMetaData(additionalAuthenticatedData);
            recordCipher.setAdditionalAuthenticatedData(record.getAuthenticatedMetaData().getValue());
            byte[] mac = recordCipher.calculateMac(ArrayConverter.concatenate(record.getAuthenticatedMetaData()
                    .getValue(), encrypted));
            setMac(record, mac);
            encrypted = ArrayConverter.concatenate(encrypted, record.getMac().getValue());
        }
        setProtocolMessageBytes(record, encrypted);
        context.increaseWriteSequenceNumber();
    }

    private boolean isEncryptThenMac(CipherSuite cipherSuite) {
        return context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC) && cipherSuite.isCBC()
                && recordCipher.isUsingMac();
    }

    private void setMac(Record record, byte[] mac) {
        record.setMac(mac);
        LOGGER.debug("MAC: " + ArrayConverter.bytesToHexString(record.getMac().getValue()));
    }

    private void setUnpaddedRecordBytes(Record record, byte[] cleanBytes) {
        record.setUnpaddedRecordBytes(ArrayConverter.concatenate(cleanBytes, record.getMac().getValue()));
        LOGGER.debug("UnpaddedRecordBytes: "
                + ArrayConverter.bytesToHexString(record.getUnpaddedRecordBytes().getValue()));
    }

    private void setPadding(Record record, byte[] padding) {
        record.setPadding(padding);
        LOGGER.debug("Padding: " + ArrayConverter.bytesToHexString(record.getPadding().getValue()));
    }

    private void setPaddingLength(Record record) {
        record.setPaddingLength(record.getPadding().getValue().length);
        LOGGER.debug("PaddingLength: " + record.getPaddingLength().getValue());
    }

    private void setPlainRecordBytes(Record record, byte[] plain) {
        record.setPlainRecordBytes(plain);
        LOGGER.debug("PlainRecordBytes: " + ArrayConverter.bytesToHexString(record.getPlainRecordBytes().getValue()));
    }

    private void setProtocolMessageBytes(Record record, byte[] encrypted) {
        record.setProtocolMessageBytes(encrypted);
        LOGGER.debug("ProtocolMessageBytes: "
                + ArrayConverter.bytesToHexString(record.getProtocolMessageBytes().getValue()));
    }

    private EncryptionRequest getEncryptionRequest(byte[] data) {
        return new EncryptionRequest(data, recordCipher.getEncryptionIV());
    }
}
