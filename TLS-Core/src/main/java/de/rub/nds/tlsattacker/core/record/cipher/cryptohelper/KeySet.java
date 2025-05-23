/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.cipher.cryptohelper;

import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class KeySet {

    private byte[] clientWriteMacSecret;
    private byte[] serverWriteMacSecret;
    private byte[] clientWriteKey;
    private byte[] serverWriteKey;
    private byte[] clientWriteIv;
    private byte[] serverWriteIv;
    private byte[] clientSnKey;
    private byte[] serverSnKey;

    private Tls13KeySetType keySetType = Tls13KeySetType.NONE;

    public KeySet() {}

    public KeySet(Tls13KeySetType keySetType) {
        this.keySetType = keySetType;
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

    public byte[] getClientSnKey() {
        return clientSnKey;
    }

    public void setClientSnKey(byte[] clientSnKey) {
        this.clientSnKey = clientSnKey;
    }

    public byte[] getServerSnKey() {
        return serverSnKey;
    }

    public void setServerSnKey(byte[] serverSnKey) {
        this.serverSnKey = serverSnKey;
    }

    public byte[] getWriteKey(ConnectionEndType connectionEndType) {
        if (connectionEndType == ConnectionEndType.CLIENT) {
            return clientWriteKey;
        } else {
            return serverWriteKey;
        }
    }

    public byte[] getReadKey(ConnectionEndType connectionEndType) {
        if (connectionEndType == ConnectionEndType.SERVER) {
            return clientWriteKey;
        } else {
            return serverWriteKey;
        }
    }

    public byte[] getReadMacSecret(ConnectionEndType connectionEndType) {
        if (connectionEndType == ConnectionEndType.SERVER) {
            return clientWriteMacSecret;
        } else {
            return serverWriteMacSecret;
        }
    }

    public byte[] getWriteMacSecret(ConnectionEndType connectionEndType) {
        if (connectionEndType == ConnectionEndType.CLIENT) {
            return clientWriteMacSecret;
        } else {
            return serverWriteMacSecret;
        }
    }

    public byte[] getWriteIv(ConnectionEndType connectionEndType) {
        if (connectionEndType == ConnectionEndType.CLIENT) {
            return clientWriteIv;
        } else {
            return serverWriteIv;
        }
    }

    public byte[] getReadIv(ConnectionEndType connectionEndType) {
        if (connectionEndType == ConnectionEndType.SERVER) {
            return clientWriteIv;
        } else {
            return serverWriteIv;
        }
    }

    public byte[] getReadSnKey(ConnectionEndType connectionEndType) {
        if (connectionEndType == ConnectionEndType.SERVER) {
            return clientSnKey;
        } else {
            return serverSnKey;
        }
    }

    public byte[] getWriteSnKey(ConnectionEndType connectionEndType) {
        if (connectionEndType == ConnectionEndType.CLIENT) {
            return clientSnKey;
        } else {
            return serverSnKey;
        }
    }

    public Tls13KeySetType getKeySetType() {
        return keySetType;
    }

    public void setKeySetType(Tls13KeySetType keySetType) {
        this.keySetType = keySetType;
    }
}
