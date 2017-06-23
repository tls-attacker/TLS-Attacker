/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.computations;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import java.math.BigInteger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DHEServerComputations extends KeyExchangeComputations {

    /**
     * server's private key
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PRIVATE_KEY)
    private ModifiableBigInteger privateKey;

    /**
     * dh modulus used for computations
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableBigInteger p;

    /**
     * dh generator used for computations
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableBigInteger g;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    private ModifiableByteArray serverRandom;

    public DHEServerComputations() {
    }

    public ModifiableBigInteger getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(ModifiableBigInteger privateKey) {
        this.privateKey = privateKey;
    }

    public void setPrivateKey(BigInteger privateKey) {
        this.privateKey = ModifiableVariableFactory.safelySetValue(this.privateKey, privateKey);
    }

    public ModifiableBigInteger getP() {
        return p;
    }

    public void setP(ModifiableBigInteger p) {
        this.p = p;
    }

    public ModifiableBigInteger getG() {
        return g;
    }

    public void setG(ModifiableBigInteger g) {
        this.g = g;
    }

    public void setP(BigInteger p) {
        this.p = ModifiableVariableFactory.safelySetValue(this.p, p);
    }

    public void setG(BigInteger g) {
        this.g = ModifiableVariableFactory.safelySetValue(this.g, g);
    }

    public ModifiableByteArray getServerRandom() {
        return serverRandom;
    }

    public void setServerRandom(ModifiableByteArray serverRandom) {
        this.serverRandom = serverRandom;
    }

    public void setServerRandom(byte[] serverRandom) {
        this.serverRandom = ModifiableVariableFactory.safelySetValue(this.serverRandom, serverRandom);
    }
}
