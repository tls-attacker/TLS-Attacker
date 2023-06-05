/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.transparency.logs;

public class CtLog {
    private String description;
    private String operator;
    private byte[] logId;
    private byte[] publicKey;

    public CtLog(String description, String operator, byte[] logId, byte[] publicKey) {
        this.description = description;
        this.operator = operator;
        this.logId = logId;
        this.publicKey = publicKey;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getOperator() {
        return operator;
    }

    public void setOperator(String operator) {
        this.operator = operator;
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
