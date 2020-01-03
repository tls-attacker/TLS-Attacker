/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import java.util.LinkedList;
import java.util.List;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;

public class EsniKeyRecord {

    private byte[] version;
    private byte[] checksum;
    private List<KeyShareStoreEntry> keyList = new LinkedList();
    private List<CipherSuite> cipherSuiteList = new LinkedList();
    private int paddedLength;
    private byte[] notBefore;
    private byte[] notAfter;
    private byte[] extensionBytes;

    public byte[] getVersion() {
        return version;
    }

    public void setVersion(byte[] version) {
        this.version = version;
    }

    public byte[] getChecksum() {
        return checksum;
    }

    public void setChecksum(byte[] checksum) {
        this.checksum = checksum;
    }

    public List<KeyShareStoreEntry> getKeyList() {
        return keyList;
    }

    public void setKeyList(List<KeyShareStoreEntry> keyList) {
        this.keyList = keyList;
    }

    public List<CipherSuite> getCipherSuiteList() {
        return cipherSuiteList;
    }

    public void setCipherSuiteList(List<CipherSuite> cipherSuiteList) {
        this.cipherSuiteList = cipherSuiteList;
    }

    public int getPaddedLength() {
        return paddedLength;
    }

    public void setPaddedLength(int paddedLength) {
        this.paddedLength = paddedLength;
    }

    public byte[] getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(byte[] notBefore) {
        this.notBefore = notBefore;
    }

    public byte[] getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(byte[] notAfter) {
        this.notAfter = notAfter;
    }

    public byte[] getExtensionBytes() {
        return extensionBytes;
    }

    public void setExtensionBytes(byte[] extensionBytes) {
        this.extensionBytes = extensionBytes;
    }
}
