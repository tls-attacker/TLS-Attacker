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
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import java.math.BigInteger;

public class RSAClientComputations extends KeyExchangeComputations {

    @ModifiableVariableProperty private ModifiableByteArray premasterSecretProtocolVersion;

    @ModifiableVariableProperty private ModifiableByteArray plainPaddedPremasterSecret;

    @ModifiableVariableProperty private ModifiableByteArray padding;

    @ModifiableVariableProperty private ModifiableBigInteger modulus;

    @ModifiableVariableProperty private ModifiableBigInteger publicExponent;

    public RSAClientComputations() {}

    public ModifiableByteArray getPlainPaddedPremasterSecret() {
        return plainPaddedPremasterSecret;
    }

    public void setPlainPaddedPremasterSecret(ModifiableByteArray plainPaddedPremasterSecret) {
        this.plainPaddedPremasterSecret = plainPaddedPremasterSecret;
    }

    public void setPlainPaddedPremasterSecret(byte[] value) {
        this.plainPaddedPremasterSecret =
                ModifiableVariableFactory.safelySetValue(this.plainPaddedPremasterSecret, value);
    }

    public ModifiableByteArray getPadding() {
        return padding;
    }

    public void setPadding(ModifiableByteArray padding) {
        this.padding = padding;
    }

    public void setPadding(byte[] padding) {
        this.padding = ModifiableVariableFactory.safelySetValue(this.padding, padding);
    }

    public ModifiableByteArray getPremasterSecretProtocolVersion() {
        return premasterSecretProtocolVersion;
    }

    public void setPremasterSecretProtocolVersion(
            ModifiableByteArray premasterSecretProtocolVersion) {
        this.premasterSecretProtocolVersion = premasterSecretProtocolVersion;
    }

    public void setPremasterSecretProtocolVersion(byte[] premasterSecretProtocolVersion) {
        this.premasterSecretProtocolVersion =
                ModifiableVariableFactory.safelySetValue(
                        this.premasterSecretProtocolVersion, premasterSecretProtocolVersion);
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

    public ModifiableBigInteger getPublicExponent() {
        return publicExponent;
    }

    public void setPublicExponent(ModifiableBigInteger publicExponent) {
        this.publicExponent = publicExponent;
    }

    public void setPublicExponent(BigInteger publicExponent) {
        this.publicExponent =
                ModifiableVariableFactory.safelySetValue(this.publicExponent, publicExponent);
    }
}
