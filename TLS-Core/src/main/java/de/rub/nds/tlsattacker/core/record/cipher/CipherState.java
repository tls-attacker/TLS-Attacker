/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;

public class CipherState {

    private ProtocolVersion protocolVersion;

    private CipherSuite cipherSuite;

    private KeySet keySet;

    private final int epoch;

    /**
     * sequence number used for the encryption
     */
    private long writeSequenceNumber = 0;

    /**
     * sequence number used for the decryption
     */
    private long readSequenceNumber = 0;

    /**
     * CipherAlgorithm algorithm (AES, ...)
     */

    private Boolean encryptThenMac;

    public CipherState(ProtocolVersion protocolVersion, CipherSuite cipherSuite, KeySet keySet, Boolean encryptThenMac,
        int epoch) {
        this.protocolVersion = protocolVersion;
        this.cipherSuite = cipherSuite;
        this.keySet = keySet;
        this.encryptThenMac = encryptThenMac;
        this.epoch = epoch;
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

    public int getEpoch() {
        return epoch;
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

    public CipherAlgorithm getCipherAlg() {
        return AlgorithmResolver.getCipher(cipherSuite);
    }
}
