/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.EsniDnsKeyRecordVersion;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EsniKeyRecord;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.Parser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EsniKeyRecordParser extends Parser<EsniKeyRecord> {

    private static final Logger LOGGER = LogManager.getLogger();
    private EsniKeyRecord record;
    private Config config;

    public EsniKeyRecordParser(int startposition, byte[] array, Config config) {
        super(startposition, array);
        this.config = config;
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
        parseExtensions(record);
        return record;
    }

    private void parseVersion(EsniKeyRecord record) {
        byte[] version = this.parseByteArrayField(ExtensionByteLength.ESNI_RECORD_VERSION);
        record.setVersion(EsniDnsKeyRecordVersion.getEnumByByte(version));
        LOGGER.debug("Version: " + record.getVersion());
    }

    private void parseChecksum(EsniKeyRecord record) {
        byte[] checksum = this.parseByteArrayField(ExtensionByteLength.ESNI_RECORD_CHECKSUM);
        record.setChecksum(checksum);
        LOGGER.debug("Checksum: " + ArrayConverter.bytesToHexString(record.getChecksum()));
    }

    private void parseKeys(EsniKeyRecord record) {
        int keysLen = this.parseIntField(ExtensionByteLength.KEY_SHARE_LIST_LENGTH);
        LOGGER.debug("KeysLength: " + keysLen);
        KeyShareStoreEntry entry;
        int i = 0;
        while (i < keysLen) {
            byte[] namedGroup = this.parseByteArrayField(ExtensionByteLength.KEY_SHARE_GROUP);
            int keyExchangeLen = this.parseIntField(ExtensionByteLength.KEY_SHARE_LENGTH);
            byte[] keyExchange = this.parseByteArrayField(keyExchangeLen);
            entry = new KeyShareStoreEntry();
            entry.setGroup(NamedGroup.getNamedGroup(namedGroup));
            entry.setPublicKey(keyExchange);
            record.getKeys().add(entry);
            i += ExtensionByteLength.KEY_SHARE_GROUP + ExtensionByteLength.KEY_SHARE_LENGTH + keyExchangeLen;
            LOGGER.debug("namedGroup: " + ArrayConverter.bytesToHexString(namedGroup));
            LOGGER.debug("keyExchange: " + ArrayConverter.bytesToHexString(keyExchange));

        }
    }

    private void parseCipherSuites(EsniKeyRecord record) {

        int cipherSuitesLen = this.parseIntField(HandshakeByteLength.CIPHER_SUITES_LENGTH);
        byte[] cipherSuitesBytes = this.parseByteArrayField(cipherSuitesLen);
        List<CipherSuite> cipherSuites = CipherSuite.getCipherSuites(cipherSuitesBytes);
        record.setCipherSuiteList(cipherSuites);
    }

    private void parsePaddedLength(EsniKeyRecord record) {
        int paddedLength = this.parseIntField(ExtensionByteLength.ESNI_RECORD_PADDED_LENGTH);
        record.setPaddedLength(paddedLength);
        LOGGER.debug("paddedLen: " + record.getPaddedLength());
    }

    private void parseNotBefore(EsniKeyRecord record) {
        byte[] notBefore = this.parseByteArrayField(ExtensionByteLength.ESNI_RECORD_NOT_BEFORE);
        record.setNotBefore(ArrayConverter.bytesToLong(notBefore));
        LOGGER.debug("notBefore: " + record.getNotBefore());
    }

    private void parseNotAfter(EsniKeyRecord record) {
        byte[] notAfter = this.parseByteArrayField(ExtensionByteLength.ESNI_RECORD_NOT_AFTER);
        record.setNotAfter(ArrayConverter.bytesToLong(notAfter));
        LOGGER.debug("notAfter: " + record.getNotAfter());
    }

    private void parseExtensions(EsniKeyRecord record) {
        int extensionsLength = this.parseIntField(HandshakeByteLength.EXTENSION_LENGTH);
        int i = 0;
        while (i < extensionsLength) {
            byte[] extensionType = this.parseByteArrayField(ExtensionByteLength.TYPE);
            int contentLength = this.parseIntField(ExtensionByteLength.EXTENSIONS_LENGTH);
            byte[] extensionContentBytes = this.parseByteArrayField(contentLength);

            ByteArrayOutputStream extensionStream = new ByteArrayOutputStream();
            try {
                extensionStream.write(extensionType);
                extensionStream.write(ArrayConverter.intToBytes(contentLength, ExtensionByteLength.EXTENSIONS_LENGTH));
                extensionStream.write(extensionContentBytes);
            } catch (IOException e) {
                LOGGER.warn("Failed to parse extensions.");
            }

            byte[] extensionBytes = extensionStream.toByteArray();
            ExtensionParser parser = ExtensionParserFactory.getExtensionParser(extensionBytes, 0, config);
            ExtensionMessage extensionMessage = parser.parse();
            record.getExtensions().add(extensionMessage);
            i = i + ExtensionByteLength.TYPE + ExtensionByteLength.EXTENSIONS_LENGTH + contentLength;
        }
    }

}
