/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher.cryptohelper;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class KeySet {

    private byte[] clientWriteMacSecret;
    private byte[] serverWriteMacSecret;
    private byte[] clientWriteKey;
    private byte[] serverWriteKey;
    private byte[] clientWriteIv;
    private byte[] serverWriteIv;

    public KeySet() {
    }

    public byte[] getClientWriteMacSecret() {
        return clientWriteMacSecret;
    }

    public void setClientWriteMacSecret(byte[] clientWriteMacSecret) {
        this.clientWriteMacSecret = clientWriteMacSecret;
    }

    public byte[] getServerWriteMacSecret() {
        return serverWriteMacSecret;
    }

    public void setServerWriteMacSecret(byte[] serverWriteMacSecret) {
        this.serverWriteMacSecret = serverWriteMacSecret;
    }

    public byte[] getClientWriteKey() {
        return clientWriteKey;
    }

    public void setClientWriteKey(byte[] clientWriteKey) {
        this.clientWriteKey = clientWriteKey;
    }

    public byte[] getServerWriteKey() {
        return serverWriteKey;
    }

    public void setServerWriteKey(byte[] serverWriteKey) {
        this.serverWriteKey = serverWriteKey;
    }

    public byte[] getClientWriteIv() {
        return clientWriteIv;
    }

    public void setClientWriteIv(byte[] clientWriteIv) {
        this.clientWriteIv = clientWriteIv;
    }

    public byte[] getServerWriteIv() {
        return serverWriteIv;
    }

    public void setServerWriteIv(byte[] serverWriteIv) {
        this.serverWriteIv = serverWriteIv;
    }

    public byte[] getKey(ConnectionEndType connectionEndType) {
        if (connectionEndType == ConnectionEndType.CLIENT) {
            return clientWriteKey;
        } else {
            return serverWriteKey;
        }
    }

    public byte[] getMacSecret(ConnectionEndType connectionEndType) {
        if (connectionEndType == ConnectionEndType.CLIENT) {
            return clientWriteMacSecret;
        } else {
            return serverWriteMacSecret;
        }
    }

    public byte[] getIv(ConnectionEndType connectionEndType) {
        if (connectionEndType == ConnectionEndType.CLIENT) {
            return clientWriteIv;
        } else {
            return serverWriteIv;
        }
    }
}
