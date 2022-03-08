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
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EsniKeyRecord;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

public class EsniKeyRecordParser extends Parser<EsniKeyRecord> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext tlsContext;

    public EsniKeyRecordParser(InputStream stream, TlsContext tlsContext) {
        super(stream);
        this.tlsContext = tlsContext;
    }

    @Override
    public void parse(EsniKeyRecord record) {
        parseVersion(record);
        parseChecksum(record);
        parseKeys(record);
        parseCipherSuites(record);
        parsePaddedLength(record);
        parseNotBefore(record);
        parseNotAfter(record);
        parseExtensions(record);
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
        // TODO this should use streams
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

        byte[] extensionListBytes = parseByteArrayField(extensionsLength);
        ExtensionListParser extensionListParser =
            new ExtensionListParser(new ByteArrayInputStream(extensionListBytes), tlsContext, false);
        List<ExtensionMessage> extensionList = new LinkedList<>();
        extensionListParser.parse(extensionList);
        record.setExtensions(extensionList);
    }

}
