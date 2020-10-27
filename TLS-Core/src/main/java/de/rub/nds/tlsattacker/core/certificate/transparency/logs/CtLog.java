/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.certificate.transparency.logs;

public class CtLog {
    private String description;
    private byte[] logId;
    private byte[] publicKey;

    public CtLog(String description, byte[] logId, byte[] publicKey) {
        this.description = description;
        this.logId = logId;
        this.publicKey = publicKey;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public byte[] getLogId() {
        return logId;
    }

    public void setLogId(byte[] logId) {
        this.logId = logId;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

}
