/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.EsniDnsKeyRecordVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import java.util.LinkedList;
import java.util.List;

public class EsniKeyRecord {

    private EsniDnsKeyRecordVersion version;
    private byte[] checksum;
    private List<KeyShareStoreEntry> keys = new LinkedList();
    private List<CipherSuite> cipherSuites = new LinkedList();
    private int paddedLength;
    private long notBefore;
    private long notAfter;
    private List<ExtensionMessage> extensions = new LinkedList();

    public EsniDnsKeyRecordVersion getVersion() {
        return version;
    }

    public void setVersion(EsniDnsKeyRecordVersion version) {
        this.version = version;
    }

    public byte[] getChecksum() {
        return checksum;
    }

    public void setChecksum(byte[] checksum) {
        this.checksum = checksum;
    }

    public List<KeyShareStoreEntry> getKeys() {
        return keys;
    }

    public void setKeys(List<KeyShareStoreEntry> keys) {
        this.keys = keys;
    }

    public List<CipherSuite> getCipherSuites() {
        return cipherSuites;
    }

    public void setCipherSuiteList(List<CipherSuite> cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    public int getPaddedLength() {
        return paddedLength;
    }

    public void setPaddedLength(int paddedLength) {
        this.paddedLength = paddedLength;
    }

    public long getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(long notBefore) {
        this.notBefore = notBefore;
    }

    public long getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(long notAfter) {
        this.notAfter = notAfter;
    }

    public List<ExtensionMessage> getExtensions() {
        return extensions;
    }

    public void setExtensions(List<ExtensionMessage> extensions) {
        this.extensions = extensions;
    }
}
