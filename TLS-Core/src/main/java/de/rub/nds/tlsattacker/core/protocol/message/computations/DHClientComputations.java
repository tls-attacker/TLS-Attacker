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
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import java.io.Serializable;
import java.math.BigInteger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DHClientComputations extends KeyExchangeComputations {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PRIVATE_KEY)
    private ModifiableBigInteger serverPublicKey;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PRIVATE_KEY)
    private ModifiableBigInteger clientPublicKey;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PRIVATE_KEY)
    private ModifiableBigInteger privateKey;

    /**
     * dh modulus used for computations
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableBigInteger modulus;

    /**
     * dh generator used for computations
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableBigInteger generator;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    private ModifiableByteArray serverRandom;

    public DHClientComputations() {
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

    public ModifiableBigInteger getModulus() {
        return modulus;
    }

    public void setModulus(ModifiableBigInteger modulus) {
        this.modulus = modulus;
    }

    public void setModulus(BigInteger modulus) {
        this.modulus = ModifiableVariableFactory.safelySetValue(this.modulus, modulus);
    }

    public ModifiableBigInteger getGenerator() {
        return generator;
    }

    public void setGenerator(ModifiableBigInteger generator) {
        this.generator = generator;
    }

    public void setGenerator(BigInteger generator) {
        this.generator = ModifiableVariableFactory.safelySetValue(this.generator, generator);
    }

    public ModifiableByteArray getServerRandom() {
        return serverRandom;
    }

    public void setServerRandom(ModifiableByteArray serverRandom) {
        this.serverRandom = serverRandom;
    }

    public ModifiableBigInteger getServerPublicKey() {
        return serverPublicKey;
    }

    public void setServerPublicKey(ModifiableBigInteger serverPublicKey) {
        this.serverPublicKey = serverPublicKey;
    }

    public void setServerPublicKey(BigInteger serverPublicKey) {
        this.serverPublicKey = ModifiableVariableFactory.safelySetValue(this.serverPublicKey, serverPublicKey);
    }

    public ModifiableBigInteger getClientPublicKey() {
        return clientPublicKey;
    }

    public void setClientPublicKey(ModifiableBigInteger clientPublicKey) {
        this.clientPublicKey = clientPublicKey;
    }

    public void setClientPublicKey(BigInteger clientPublicKey) {
        this.clientPublicKey = ModifiableVariableFactory.safelySetValue(this.clientPublicKey, clientPublicKey);
    }
}
