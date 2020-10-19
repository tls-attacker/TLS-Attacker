/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.computations;

import java.math.BigInteger;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.tlsattacker.core.config.Config;

public class RSAServerComputations extends KeyExchangeComputations {
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableBigInteger modulus;
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableBigInteger publicExponent;

    @Override
    public void setSecretsInConfig(Config config) {
        config.setDefaultServerRSAModulus(modulus.getValue());
        config.setDefaultServerRSAPublicKey(publicExponent.getValue());
        config.setDefaultServerRSAPrivateKey(getPrivateKey().getValue());
    }

    // #region getters/setters
    public void setModulus(BigInteger modulus) {
        this.modulus = ModifiableVariableFactory.safelySetValue(this.modulus, modulus);
    }

    public ModifiableBigInteger getModulus() {
        return modulus;
    }

    public void setPublicExponent(BigInteger publicExponent) {
        this.publicExponent = ModifiableVariableFactory.safelySetValue(this.publicExponent, publicExponent);
    }

    public ModifiableBigInteger getPublicExponent() {
        return publicExponent;
    }
    // #endregion

}
