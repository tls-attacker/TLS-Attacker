/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.computations;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import java.math.BigInteger;

public class DHClientComputations extends KeyExchangeComputations {

    @ModifiableVariableProperty private ModifiableBigInteger publicKey;

    /** dh modulus used for computations */
    @ModifiableVariableProperty private ModifiableBigInteger modulus;

    /** dh generator used for computations */
    @ModifiableVariableProperty private ModifiableBigInteger generator;

    public DHClientComputations() {}

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

    public ModifiableBigInteger getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(ModifiableBigInteger publicKey) {
        this.publicKey = publicKey;
    }

    public void setPublicKey(BigInteger serverPublicKey) {
        this.publicKey = ModifiableVariableFactory.safelySetValue(this.publicKey, serverPublicKey);
    }
}
