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
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.extension.esni.EsniKeyRecord;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;

public class EsniKeyParser extends Parser<EsniKeyRecord> {

    private static final Logger LOGGER = LogManager.getLogger();
    private EsniKeyRecord esniKeys;

    public EsniKeyParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public EsniKeyRecord parse() {
        esniKeys = new EsniKeyRecord();
        parseVersion(esniKeys);
        parseChecksum(esniKeys);
        parseKeys(esniKeys);
        parseCipherSuites(esniKeys);
        parsePaddedLength(esniKeys);
        parseNotBefore(esniKeys);
        parseNotAfter(esniKeys);
        parsenotExtensions(esniKeys);
        return esniKeys;
    }

    private void parseVersion(EsniKeyRecord esniKeys) {
        byte[] version = this.parseByteArrayField(ExtensionByteLength.ESNI_RECORD_VERSION);
        esniKeys.setVersion(version);
        LOGGER.debug("Version: " + ArrayConverter.bytesToHexString(version));

    }

    private void parseChecksum(EsniKeyRecord esniKeys) {
        byte[] checksum = this.parseByteArrayField(ExtensionByteLength.ESNI_RECORD_CHECKSUM);
        esniKeys.setChecksum(checksum);
        LOGGER.debug("Checksum: " + ArrayConverter.bytesToHexString(checksum));
    }

    private void parseKeys(EsniKeyRecord esniKeys) {
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
            esniKeys.getKeyList().add(entry);
            i += ExtensionByteLength.ESNI_RECORD_NAMEDGROUP + ExtensionByteLength.ESNI_RECORD_KEY_LENGTH
                    + keyExchangeLen;
            LOGGER.debug("namedGroup: " + ArrayConverter.bytesToHexString(namedGroup));
            LOGGER.debug("keyExchange: " + ArrayConverter.bytesToHexString(keyExchange));
        }
    }

    private void parseCipherSuites(EsniKeyRecord esniKeys) {
        int cipherSuitesLen = this.parseIntField(ExtensionByteLength.ESNI_RECORD_CIPHER_SUITES_LENGTH);
        for (int i = 0; i < cipherSuitesLen; i += ExtensionByteLength.ESNI_RECORD_CIPHER_SUITE) {
            byte[] cipherSuite = this.parseByteArrayField(ExtensionByteLength.ESNI_RECORD_CIPHER_SUITE);
            esniKeys.getCipherSuiteList().add(cipherSuite);
            LOGGER.debug("cipherSuite: " + ArrayConverter.bytesToHexString(cipherSuite));
        }
    }

    private void parsePaddedLength(EsniKeyRecord esniKeys) {
        int paddedLength = this.parseIntField(ExtensionByteLength.ESNI_RECORD_PADDED_LENGTH);
        esniKeys.setPaddedLength(paddedLength);
        LOGGER.debug("paddedLen: " + paddedLength);
    }

    private void parseNotBefore(EsniKeyRecord esniKeys) {
        byte[] notBefore = this.parseByteArrayField(ExtensionByteLength.ESNI_RECORD_NOT_BEFORE);
        LOGGER.debug("notBefore: " + ArrayConverter.bytesToHexString(notBefore));
    }

    private void parseNotAfter(EsniKeyRecord esniKeys) {
        byte[] notAfter = this.parseByteArrayField(ExtensionByteLength.ESNI_RECORD_NOT_AFTER);
        LOGGER.debug("notAfter: " + ArrayConverter.bytesToHexString(notAfter));
    }

    private void parsenotExtensions(EsniKeyRecord esniKeys) {
        int extensionsLen = this.parseIntField(ExtensionByteLength.ESNI_RECORD_EXTENSIONS);
        byte[] extensionsBytes = this.parseByteArrayField(extensionsLen);
        LOGGER.debug("extensionsBytesLen: " + extensionsLen);
        LOGGER.debug("extensionsBytes: " + ArrayConverter.bytesToHexString(extensionsBytes));
    }

}
