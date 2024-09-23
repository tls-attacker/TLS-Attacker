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
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import java.math.BigInteger;

/**
 * These computations are used for empty client key exchange messages which are sent if client
 * authentication is used and the public key from the certificate can be used as a static dh key.
 * Either for ECDH or DH.
 */
public class EmptyClientComputations extends KeyExchangeComputations {

    private ModifiableBigInteger dhModulus;

    private ModifiableBigInteger dhGenerator;

    private ModifiableBigInteger dhPeerPublicKey;

    private ModifiableBigInteger ecPublicKeyX;

    private ModifiableBigInteger ecPublicKeyY;

    public EmptyClientComputations() {}

    public ModifiableBigInteger getDhModulus() {
        return dhModulus;
    }

    public void setDhModulus(ModifiableBigInteger dhModulus) {
        this.dhModulus = dhModulus;
    }

    public void setDhModulus(BigInteger dhModulus) {
        this.dhModulus = ModifiableVariableFactory.safelySetValue(this.dhModulus, dhModulus);
    }

    public ModifiableBigInteger getDhGenerator() {
        return dhGenerator;
    }

    public void setDhGenerator(ModifiableBigInteger dhGenerator) {
        this.dhGenerator = dhGenerator;
    }

    public void setDhGenerator(BigInteger dhGenerator) {
        this.dhGenerator = ModifiableVariableFactory.safelySetValue(this.dhGenerator, dhGenerator);
    }

    public ModifiableBigInteger getDhPeerPublicKey() {
        return dhPeerPublicKey;
    }

    public void setDhPeerPublicKey(ModifiableBigInteger dhPeerPublicKey) {
        this.dhPeerPublicKey = dhPeerPublicKey;
    }

    public void setDhPeerPublicKey(BigInteger dhPeerPublicKey) {
        this.dhPeerPublicKey =
                ModifiableVariableFactory.safelySetValue(this.dhPeerPublicKey, dhPeerPublicKey);
    }

    public ModifiableBigInteger getEcPublicKeyX() {
        return ecPublicKeyX;
    }

    public void setEcPublicKeyX(ModifiableBigInteger ecPublicKeyX) {
        this.ecPublicKeyX = ecPublicKeyX;
    }

    public void setEcPublicKeyX(BigInteger ecPublicKeyX) {
        this.ecPublicKeyX =
                ModifiableVariableFactory.safelySetValue(this.ecPublicKeyX, ecPublicKeyX);
    }

    public ModifiableBigInteger getEcPublicKeyY() {
        return ecPublicKeyY;
    }

    public void setEcPublicKeyY(ModifiableBigInteger ecPublicKeyY) {
        this.ecPublicKeyY = ecPublicKeyY;
    }

    public void setEcPublicKeyY(BigInteger ecPublicKeyY) {
        this.ecPublicKeyY =
                ModifiableVariableFactory.safelySetValue(this.ecPublicKeyY, ecPublicKeyY);
    }
}
