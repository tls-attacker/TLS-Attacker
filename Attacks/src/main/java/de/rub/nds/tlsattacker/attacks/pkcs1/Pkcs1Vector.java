/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.pkcs1;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.attacks.general.Vector;
import java.util.Arrays;

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

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 41 * hash + Arrays.hashCode(this.plainValue);
        hash = 41 * hash + Arrays.hashCode(this.encryptedValue);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Pkcs1Vector other = (Pkcs1Vector) obj;
        if (!Arrays.equals(this.plainValue, other.plainValue)) {
            return false;
        }
        if (!Arrays.equals(this.encryptedValue, other.encryptedValue)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "" + name + "{" + "plainValue=" + ArrayConverter.bytesToHexString(plainValue) + ", encryptedValue="
            + ArrayConverter.bytesToHexString(encryptedValue) + '}';
    }
}
