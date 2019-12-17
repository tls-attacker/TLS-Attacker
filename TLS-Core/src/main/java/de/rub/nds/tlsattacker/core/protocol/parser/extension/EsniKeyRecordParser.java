/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.extension.esni.EsniKeyRecord;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;

public class EsniKeyRecordParser extends Parser<EsniKeyRecord> {

    private static final Logger LOGGER = LogManager.getLogger();
    private EsniKeyRecord record;

    public EsniKeyRecordParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public EsniKeyRecord parse() {
        record = new EsniKeyRecord();
        parseVersion(record);
        parseChecksum(record);
        parseKeys(record);
        parseCipherSuites(record);
        parsePaddedLength(record);
        parseNotBefore(record);
        parseNotAfter(record);
        parsenotExtensions(record);
        return record;
    }

    private void parseVersion(EsniKeyRecord record) {
        byte[] version = this.parseByteArrayField(ExtensionByteLength.ESNI_RECORD_VERSION);
        record.setVersion(version);
        LOGGER.debug("Version: " + ArrayConverter.bytesToHexString(record.getVersion()));

    }

    private void parseChecksum(EsniKeyRecord record) {
        byte[] checksum = this.parseByteArrayField(ExtensionByteLength.ESNI_RECORD_CHECKSUM);
        record.setChecksum(checksum);
        LOGGER.debug("Checksum: " + ArrayConverter.bytesToHexString(record.getChecksum()));
    }

    private void parseKeys(EsniKeyRecord record) {
        int keysLen = this.parseIntField(ExtensionByteLength.ESNI_RECORD_KEYS_LENGTH);
        LOGGER.debug("KeysLength: " + keysLen);
        KeyShareStoreEntry entry;
        int i = 0;
        while (i < keysLen) {
            byte[] namedGroup = this.parseByteArrayField(ExtensionByteLength.ESNI_RECORD_NAMEDGROUP);
            int keyExchangeLen = this.parseIntField(ExtensionByteLength.ESNI_RECORD_KEY_LENGTH);
            byte[] keyExchange = this.parseByteArrayField(keyExchangeLen);
            entry = new KeyShareStoreEntry();
            entry.setGroup(NamedGroup.getNamedGroup(namedGroup));
            entry.setPublicKey(keyExchange);
            record.getKeyList().add(entry);
            i += ExtensionByteLength.ESNI_RECORD_NAMEDGROUP + ExtensionByteLength.ESNI_RECORD_KEY_LENGTH
                    + keyExchangeLen;
            LOGGER.debug("namedGroup: " + ArrayConverter.bytesToHexString(namedGroup));
            LOGGER.debug("keyExchange: " + ArrayConverter.bytesToHexString(keyExchange));

        }
    }

    private void parseCipherSuites(EsniKeyRecord record) {
        int cipherSuitesLen = this.parseIntField(ExtensionByteLength.ESNI_RECORD_CIPHER_SUITES_LENGTH);
        for (int i = 0; i < cipherSuitesLen; i += ExtensionByteLength.ESNI_RECORD_CIPHER_SUITE) {
            byte[] cipherSuite = this.parseByteArrayField(ExtensionByteLength.ESNI_RECORD_CIPHER_SUITE);
            record.getCipherSuiteList().add(CipherSuite.getCipherSuite(cipherSuite));
            LOGGER.debug("cipherSuite: " + ArrayConverter.bytesToHexString(cipherSuite));
        }
    }

    private void parsePaddedLength(EsniKeyRecord record) {
        int paddedLength = this.parseIntField(ExtensionByteLength.ESNI_RECORD_PADDED_LENGTH);
        record.setPaddedLength(paddedLength);
        LOGGER.debug("paddedLen: " + record.getPaddedLength());
    }

    private void parseNotBefore(EsniKeyRecord record) {
        byte[] notBefore = this.parseByteArrayField(ExtensionByteLength.ESNI_RECORD_NOT_BEFORE);
        record.setNotBefore(notBefore);
        LOGGER.debug("notBefore: " + ArrayConverter.bytesToHexString(record.getNotBefore()));
    }

    private void parseNotAfter(EsniKeyRecord record) {
        byte[] notAfter = this.parseByteArrayField(ExtensionByteLength.ESNI_RECORD_NOT_AFTER);
        record.setNotAfter(notAfter);
        LOGGER.debug("notAfter: " + ArrayConverter.bytesToHexString(record.getNotAfter()));
    }

    private void parsenotExtensions(EsniKeyRecord record) {
        int extensionsLen = this.parseIntField(ExtensionByteLength.ESNI_RECORD_EXTENSIONS);
        byte[] extensionBytes = this.parseByteArrayField(extensionsLen);
        record.setExtensionBytes(extensionBytes);
        LOGGER.debug("extensionsBytesLen: " + extensionsLen);
        LOGGER.debug("extensionsBytes: " + ArrayConverter.bytesToHexString(record.getExtensionBytes()));
    }

}
