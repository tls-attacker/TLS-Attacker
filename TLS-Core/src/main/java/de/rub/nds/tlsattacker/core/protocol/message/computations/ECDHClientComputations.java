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
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.crypto.ec.CustomECPoint;
import java.math.BigInteger;

public class ECDHClientComputations extends KeyExchangeComputations {

    // This is the public key used for the computation
    private ModifiableBigInteger publicKeyX;

    private ModifiableBigInteger publicKeyY;

    private ModifiableBigInteger computedPublicKeyX;

    private ModifiableBigInteger computedPublicKeyY;

    public CustomECPoint getPublicKey() {
        return new CustomECPoint(publicKeyX.getValue(), publicKeyY.getValue());
    }

    public void setPublicKey(BigInteger x, BigInteger y) {
        this.publicKeyX = ModifiableVariableFactory.safelySetValue(this.publicKeyX, x);
        this.publicKeyY = ModifiableVariableFactory.safelySetValue(this.publicKeyY, y);
    }

    @Override
    public void setSecretsInConfig(Config config) {
        config.setDefaultClientEcPrivateKey(getPrivateKey().getValue());
    }

    public ModifiableBigInteger getComputedPublicKeyX() {
        return computedPublicKeyX;
    }

    public void setComputedPublicKeyX(ModifiableBigInteger computedPublicKeyX) {
        this.computedPublicKeyX = computedPublicKeyX;
    }

    public void setComputedPublicKeyX(BigInteger computedPublicKeyX) {
        this.computedPublicKeyX = ModifiableVariableFactory.safelySetValue(this.computedPublicKeyX, computedPublicKeyX);
    }

    public ModifiableBigInteger getComputedPublicKeyY() {
        return computedPublicKeyY;
    }

    public void setComputedPublicKeyY(BigInteger computedPublicKeyY) {
        this.computedPublicKeyY = ModifiableVariableFactory.safelySetValue(this.computedPublicKeyY, computedPublicKeyY);
    }

    public void setComputedPublicKeyY(ModifiableBigInteger computedPublicKeyY) {
        this.computedPublicKeyY = computedPublicKeyY;
    }
}
