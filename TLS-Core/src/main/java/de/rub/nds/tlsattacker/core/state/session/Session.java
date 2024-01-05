/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.state.session;

public abstract class Session {
    private byte[] masterSecret;
    protected boolean isIdSession;

    public Session(byte[] masterSecret) {
        this.masterSecret = masterSecret;
    }

    public byte[] getMasterSecret() {
        return masterSecret;
    }

    public void setMasterSecret(byte[] masterSecret) {
        this.masterSecret = masterSecret;
    }

    public boolean isIdSession() {
        return isIdSession;
    }

    public boolean isTicketSession() {
        return !isIdSession;
    }
}
