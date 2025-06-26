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
import de.rub.nds.modifiablevariable.ModifiableVariableHolder;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import java.math.BigInteger;

public abstract class KeyExchangeComputations extends ModifiableVariableHolder {

    @ModifiableVariableProperty protected ModifiableByteArray premasterSecret;

    @ModifiableVariableProperty protected ModifiableByteArray clientServerRandom;

    @ModifiableVariableProperty private ModifiableBigInteger privateKey;

    public ModifiableByteArray getPremasterSecret() {
        return premasterSecret;
    }

    public void setPremasterSecret(ModifiableByteArray premasterSecret) {
        this.premasterSecret = premasterSecret;
    }

    public void setPremasterSecret(byte[] premasterSecret) {
        this.premasterSecret =
                ModifiableVariableFactory.safelySetValue(this.premasterSecret, premasterSecret);
    }

    public ModifiableByteArray getClientServerRandom() {
        return clientServerRandom;
    }

    public void setClientServerRandom(ModifiableByteArray clientServerRandom) {
        this.clientServerRandom = clientServerRandom;
    }

    public void setClientServerRandom(byte[] random) {
        this.clientServerRandom =
                ModifiableVariableFactory.safelySetValue(this.clientServerRandom, random);
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
}
