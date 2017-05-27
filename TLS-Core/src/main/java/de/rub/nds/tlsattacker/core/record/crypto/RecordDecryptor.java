/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.crypto;

import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class RecordDecryptor extends Decryptor<Record> {

    private final ProtocolVersion version;

    public RecordDecryptor(RecordCipher recordCipher, ProtocolVersion version) {
        super(recordCipher);
        this.version = version;
    }

    @Override
    public void decrypt(Record record) {
        byte[] encrypted = record.getProtocolMessageBytes().getValue();
        byte[] decrypted = recordCipher.decrypt(encrypted);
        record.setPlainRecordBytes(decrypted);
        if (recordCipher.isUsePadding()) {
            LOGGER.debug("Padded data after decryption:  {}", ArrayConverter.bytesToHexString(decrypted));
            if (version != ProtocolVersion.TLS13) {
                int paddingLength = parsePaddingLength(decrypted);
                record.setPaddingLength(paddingLength);
                byte[] unpadded = parseUnpadded(decrypted, paddingLength);
                record.setUnpaddedRecordBytes(unpadded);
                byte[] padding = parsePadding(decrypted, paddingLength);
                record.setPadding(padding);
                LOGGER.debug("Unpadded data:  {}", ArrayConverter.bytesToHexString(unpadded));
            } else {
                byte[] unpadded = parseUnpaddedTLS13(decrypted);
                LOGGER.debug("Unpadded data:  {}", ArrayConverter.bytesToHexString(unpadded));
                byte contentMessageType = parseContentMessageType(unpadded);
                record.setContentMessageType(ProtocolMessageType.getContentType(contentMessageType));
                byte[] unpaddedAndWithoutType = Arrays.copyOf(unpadded, unpadded.length - 1);
                record.setUnpaddedRecordBytes(unpaddedAndWithoutType);
                byte[] padding = parsePadding(decrypted, decrypted.length - unpadded.length);
                record.setPadding(padding);
                record.setPaddingLength(padding.length);
            }
        } else {
            record.setPaddingLength(0);
            record.setPadding(new byte[0]);
            record.setUnpaddedRecordBytes(decrypted);
        }
        byte[] cleanBytes;
        if (recordCipher.isUseMac()) {
            byte[] mac = parseMac(record.getUnpaddedRecordBytes().getValue());
            record.setMac(mac);
            cleanBytes = removeMac(record.getUnpaddedRecordBytes().getValue());
        } else {
            record.setMac(new byte[0]);
            cleanBytes = record.getUnpaddedRecordBytes().getValue();
        }
        record.setCleanProtocolMessageBytes(cleanBytes);
    }

    /**
     * Last byte contains the padding length. If there is no last byte, throw a
     * decyption exception (instead of index out of bounds)
     *
     * @param decrypted
     * @return
     */
    private int parsePaddingLength(byte[] decrypted) {
        if (decrypted.length == 0) {
            throw new CryptoException("Could not extract padding.");
        }
        return decrypted[decrypted.length - 1];
    }

    private byte[] parseUnpadded(byte[] decrypted, int paddingLength) {
        if (paddingLength > decrypted.length) {
            throw new CryptoException("Could not unpad decrypted Data. Padding length greater than data length");
        }
        int paddingStart = decrypted.length - paddingLength - 1;
        return Arrays.copyOf(decrypted, paddingStart);
    }

    private byte[] parseUnpaddedTLS13(byte[] decrypted) {
        if (decrypted.length == 0) {
            throw new CryptoException("Could not extract padding.");
        }
        int i = decrypted.length - 1;
        while (i >= 0 && decrypted[i] == 0) {
            --i;
        }
        return Arrays.copyOf(decrypted, i + 1);
    }

    private byte[] parsePadding(byte[] decrypted, int paddingLength) {
        if (paddingLength > decrypted.length) {
            throw new CryptoException("Could parse Padding. Padding length greater than data length");
        }
        int paddingStart = decrypted.length - paddingLength - 1;
        return Arrays.copyOfRange(decrypted, paddingStart, decrypted.length);
    }

    private byte[] parseMac(byte[] unpadded) {
        if (unpadded.length - recordCipher.getMacLength() < 0) {
            throw new CryptoException("Could not parse MAC, not enough bytes left");
        }
        return Arrays.copyOfRange(unpadded, (unpadded.length - recordCipher.getMacLength()), unpadded.length);
    }

    private byte[] removeMac(byte[] unpadded) {
        return Arrays.copyOf(unpadded, (unpadded.length - recordCipher.getMacLength()));
    }

    private byte parseContentMessageType(byte[] unpadded) {
        if (unpadded.length == 0) {
            throw new CryptoException("Could not extract content tpye of message.");
        }
        return unpadded[unpadded.length - 1];
    }
}
