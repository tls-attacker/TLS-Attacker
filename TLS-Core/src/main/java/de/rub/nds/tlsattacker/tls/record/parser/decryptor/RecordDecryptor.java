/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.record.parser.decryptor;

import de.rub.nds.tlsattacker.tls.crypto.TlsRecordBlockCipher;
import de.rub.nds.tlsattacker.tls.exceptions.CryptoException;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author Robert Merget <robert.merget@rub.de>
 */
public class RecordDecryptor extends Decryptor<Record> {

    private static final Logger LOGGER = LogManager.getLogger("DECRYPTOR");

    private TlsRecordBlockCipher recordCipher;
    private boolean decryptReceiving;

    public RecordDecryptor(TlsRecordBlockCipher recordCipher, boolean decryptReceiving) {
        this.recordCipher = recordCipher;
        this.decryptReceiving = decryptReceiving;
    }

    @Override
    public void decrypt(Record record) {
        if (decryptReceiving) {
            byte[] encrypted = record.getProtocolMessageBytes().getValue();
            record.setEncryptedProtocolMessageBytes(encrypted);
            byte[] decrypted = recordCipher.decrypt(encrypted);
            record.setPlainRecordBytes(decrypted);
            LOGGER.debug("Padded data after decryption:  {}", ArrayConverter.bytesToHexString(decrypted));
            int paddingLength = parsePaddingLength(decrypted);
            record.setPaddingLength(paddingLength);
            byte[] unpadded = parseUnpadded(decrypted, paddingLength);
            byte[] padding = parsePadding(decrypted, paddingLength);
            record.setPadding(padding);
            LOGGER.debug("Unpadded data:  {}", ArrayConverter.bytesToHexString(unpadded));
            byte[] mac = parseMac(unpadded);
            record.setMac(mac);
            byte[] cleanBytes = removeMac(unpadded);
            record.setCleanProtocolMessageBytes(cleanBytes);
        } else {
            record.setCleanProtocolMessageBytes(record.getProtocolMessageBytes().getValue());
        }
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
        return Arrays.copyOfRange(unpadded, (unpadded.length - recordCipher.getMacLength()),
                unpadded.length);
    }

    private byte[] removeMac(byte[] unpadded) {
        return Arrays.copyOf(unpadded,
                (unpadded.length - recordCipher.getMacLength()));
    }

}
