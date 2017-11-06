/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.state;

public class Session {

    private byte[] sessionId;

    private byte[] masterSecret;

    public Session(byte[] sessionId, byte[] masterSecret) {
        this.sessionId = sessionId;
        this.masterSecret = masterSecret;
    }

    public byte[] getSessionId() {
        return sessionId;
    }

    public void setSessionId(byte[] sessionId) {
        this.sessionId = sessionId;
    }

    public byte[] getMasterSecret() {
        return masterSecret;
    }

    public void setMasterSecret(byte[] masterSecret) {
        this.masterSecret = masterSecret;
    }
}
