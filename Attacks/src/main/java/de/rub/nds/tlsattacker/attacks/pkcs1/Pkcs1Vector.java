/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.pkcs1;

/**
 *
 *
 */
public class Pkcs1Vector {

    private String description;

    private byte[] plainValue;

    private byte[] encryptedValue;

    /**
     *
     * @param description
     * @param value
     */
    public Pkcs1Vector(String description, byte[] value) {
        this.description = description;
        this.plainValue = value;
    }

    /**
     *
     * @return
     */
    public String getDescription() {
        return description;
    }

    /**
     *
     * @param description
     */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     *
     * @return
     */
    public byte[] getPlainValue() {
        return plainValue;
    }

    /**
     *
     * @param plainValue
     */
    public void setPlainValue(byte[] plainValue) {
        this.plainValue = plainValue;
    }

    /**
     *
     * @return
     */
    public byte[] getEncryptedValue() {
        return encryptedValue;
    }

    /**
     *
     * @param encryptedValue
     */
    public void setEncryptedValue(byte[] encryptedValue) {
        this.encryptedValue = encryptedValue;
    }
}
