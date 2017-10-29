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
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class SRPServerComputations extends KeyExchangeComputations {

    /**
     * server's private key
     */
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

    /**
     * SRP salt
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray salt;

    private ModifiableByteArray srpIdentity;
    private ModifiableByteArray srpPassword;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    private ModifiableByteArray serverRandom;

    public SRPServerComputations() {
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

    public ModifiableByteArray getSRPIdentity() {
        return srpIdentity;
    }

    public void setSRPIdentity(ModifiableByteArray srpIdentity) {
        this.srpIdentity = srpIdentity;
    }

    public void setSRPIdentity(byte[] srpIdentity) {
        this.srpIdentity = ModifiableVariableFactory.safelySetValue(this.srpIdentity, srpIdentity);
    }

    public ModifiableByteArray getSRPPassword() {
        return srpPassword;
    }

    public void setSRPPassword(ModifiableByteArray srpPassword) {
        this.srpPassword = srpPassword;
    }

    public void setSRPPassword(byte[] srpPassword) {
        this.srpPassword = ModifiableVariableFactory.safelySetValue(this.srpPassword, srpPassword);
    }

    public ModifiableByteArray getSalt() {
        return salt;
    }

    public void setSalt(ModifiableByteArray salt) {
        this.salt = salt;
    }

    public void setSalt(byte[] salt) {
        this.salt = ModifiableVariableFactory.safelySetValue(this.salt, salt);
    }

    public ModifiableBigInteger getModulus() {
        return modulus;
    }

    public void setModulus(ModifiableBigInteger modulus) {
        this.modulus = modulus;
    }

    public ModifiableBigInteger getGenerator() {
        return generator;
    }

    public void setGenerator(ModifiableBigInteger generator) {
        this.generator = generator;
    }

    public void setModulus(BigInteger modulus) {
        this.modulus = ModifiableVariableFactory.safelySetValue(this.modulus, modulus);
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

    public void setServerRandom(byte[] serverRandom) {
        this.serverRandom = ModifiableVariableFactory.safelySetValue(this.serverRandom, serverRandom);
    }
}
