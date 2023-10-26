/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;

public class CipherState {

    private ProtocolVersion protocolVersion;

    private CipherSuite cipherSuite;

    private KeySet keySet;

    /** sequence number used for the encryption */
    private long writeSequenceNumber = 0;

    /** sequence number used for the decryption */
    private long readSequenceNumber = 0;

    private byte[] connectionId = null;

    private Boolean encryptThenMac;

    public CipherState(
            ProtocolVersion protocolVersion,
            CipherSuite cipherSuite,
            KeySet keySet,
            Boolean encryptThenMac) {
        this.protocolVersion = protocolVersion;
        this.cipherSuite = cipherSuite;
        this.keySet = keySet;
        this.encryptThenMac = encryptThenMac;
        this.connectionId = null;
    }

    public CipherState(
            ProtocolVersion protocolVersion,
            CipherSuite cipherSuite,
            KeySet keySet,
            Boolean encryptThenMac,
            byte[] connectionId) {
        this.protocolVersion = protocolVersion;
        this.cipherSuite = cipherSuite;
        this.keySet = keySet;
        this.encryptThenMac = encryptThenMac;
        this.connectionId = connectionId;
    }

    public Boolean isEncryptThenMac() {
        return encryptThenMac;
    }

    public void setEncryptThenMac(Boolean encryptThenMac) {
        this.encryptThenMac = encryptThenMac;
    }

    public ProtocolVersion getVersion() {
        return protocolVersion;
    }

    public void setVersion(ProtocolVersion protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    public CipherSuite getCipherSuite() {
        return cipherSuite;
    }

    public void setCipherSuite(CipherSuite cipherSuite) {
        this.cipherSuite = cipherSuite;
    }

    public KeySet getKeySet() {
        return keySet;
    }

    public void setKeySet(KeySet keySet) {
        this.keySet = keySet;
    }

    public long getWriteSequenceNumber() {
        return writeSequenceNumber;
    }

    public void setWriteSequenceNumber(long writeSequenceNumber) {
        this.writeSequenceNumber = writeSequenceNumber;
    }

    public void increaseWriteSequenceNumber() {
        writeSequenceNumber += 1;
    }

    public long getReadSequenceNumber() {
        return readSequenceNumber;
    }

    public void setReadSequenceNumber(long readSequenceNumber) {
        this.readSequenceNumber = readSequenceNumber;
    }

    public void increaseReadSequenceNumber() {
        readSequenceNumber += 1;
    }

    public byte[] getConnectionId() {
        return connectionId;
    }

    public void setConnectionId(byte[] connectionId) {
        this.connectionId = connectionId;
    }

    public CipherAlgorithm getCipherAlg() {
        return AlgorithmResolver.getCipher(cipherSuite);
    }
}
