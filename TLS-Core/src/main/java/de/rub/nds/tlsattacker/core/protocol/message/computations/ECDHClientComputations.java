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

    private ModifiableBigInteger serverPublicKeyX;

    private ModifiableBigInteger serverPublicKeyY;

    private CustomECPoint clientPublicKey;

    public CustomECPoint getClientPublicKey() {
        return clientPublicKey;
    }

    public void setClientPublicKey(CustomECPoint clientPublicKey) {
        this.clientPublicKey = clientPublicKey;
    }

    public ModifiableBigInteger getServerPublicKeyX() {
        return serverPublicKeyX;
    }

    public void setServerPublicKeyX(ModifiableBigInteger serverPublicKeyX) {
        this.serverPublicKeyX = serverPublicKeyX;
    }

    public void setServerPublicKeyX(BigInteger serverPublicKeyX) {
        this.serverPublicKeyX = ModifiableVariableFactory.safelySetValue(this.serverPublicKeyX, serverPublicKeyX);
    }

    public ModifiableBigInteger getServerPublicKeyY() {
        return serverPublicKeyY;
    }

    public void setServerPublicKeyY(ModifiableBigInteger serverPublicKeyY) {
        this.serverPublicKeyY = serverPublicKeyY;
    }

    public void setServerPublicKeyY(BigInteger serverPublicKeyY) {
        this.serverPublicKeyY = ModifiableVariableFactory.safelySetValue(this.serverPublicKeyY, serverPublicKeyY);
    }

    @Override
    public void setSecretsInConfig(Config config) {
        config.setDefaultClientEcPrivateKey(getPrivateKey().getValue());
    }
}
