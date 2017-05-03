/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.constants;

import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.Serializable;
import java.math.BigInteger;
import org.bouncycastle.util.BigIntegers;

/**
 * @author Nurullah Erinola
 */
public class KeyShareEntry implements Serializable {

    private NamedCurve group;

    private int keyExchangeLength;

    private byte[] serializedPublicKey;

    public KeyShareEntry() {

    }

    public KeyShareEntry(NamedCurve group, int keyExchangeLength, byte[] serializedPublicKey) {
        this.group = group;
        this.keyExchangeLength = keyExchangeLength;
        this.serializedPublicKey = serializedPublicKey;
    }

    public byte[] getByteValue() {
        byte[] result = ArrayConverter.concatenate(group.getValue(),
                BigIntegers.asUnsignedByteArray(BigInteger.valueOf(keyExchangeLength)), serializedPublicKey);
        return result;
    }

    public NamedCurve getGroup() {
        return group;
    }

    public void setGroup(NamedCurve group) {
        this.group = group;
    }

    public int getKeyExchangeLength() {
        return keyExchangeLength;
    }

    public void setKeyExchangeLength(int keyExchangeLength) {
        this.keyExchangeLength = keyExchangeLength;
    }

    public byte[] getSerializedPublicKey() {
        return serializedPublicKey;
    }

    public void setSerializedPublicKey(byte[] serializedPublicKey) {
        this.serializedPublicKey = serializedPublicKey;
    }

}
