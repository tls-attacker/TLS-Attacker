/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.pkcs1;

import de.rub.nds.tlsattacker.attacks.general.Vector;

/**
 *
 *
 */
public class Pkcs1Vector implements Vector {

    private String name;

    private byte[] plainValue;

    private byte[] encryptedValue;

    private Pkcs1Vector() {
    }

    /**
     *
     * @param name
     * @param value
     */
    public Pkcs1Vector(String name, byte[] value) {
        this.name = name;
        this.plainValue = value;
    }

    public void setName(String name) {
        this.name = name;
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

    @Override
    public String getName() {
        return name;
    }
}
