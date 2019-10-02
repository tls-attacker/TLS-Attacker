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
import java.math.BigInteger;

public class ECDHClientComputations extends KeyExchangeComputations {

    private ModifiableBigInteger publicKeyX;

    private ModifiableBigInteger publicKeyY;

    @Override
    public void setSecretsInConfig(Config config) {
        config.setDefaultClientEcPrivateKey(getPrivateKey().getValue());
    }

    public ModifiableBigInteger getPublicKeyX() {
        return publicKeyX;
    }

    public void setPublicKeyX(ModifiableBigInteger publicKeyX) {
        this.publicKeyX = publicKeyX;
    }

    public void setPublicKeyX(BigInteger computedPublicKeyX) {
        this.publicKeyX = ModifiableVariableFactory.safelySetValue(this.publicKeyX, computedPublicKeyX);
    }

    public ModifiableBigInteger getPublicKeyY() {
        return publicKeyY;
    }

    public void setPublicKeyY(BigInteger computedPublicKeyY) {
        this.publicKeyY = ModifiableVariableFactory.safelySetValue(this.publicKeyY, computedPublicKeyY);
    }

    public void setPublicKeyY(ModifiableBigInteger publicKeyY) {
        this.publicKeyY = publicKeyY;
    }
}
