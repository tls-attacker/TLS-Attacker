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
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.config.Config;

public class PSKRSAPremasterComputations extends KeyExchangeComputations {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PADDING)
    private ModifiableByteArray padding;

    private ModifiableByteArray encryptedPremasterSecret;

    private ModifiableByteArray psk;

    public PSKRSAPremasterComputations() {
    }

    @Override
    public ModifiableByteArray getPremasterSecret() {
        return premasterSecret;
    }

    @Override
    public void setPremasterSecret(ModifiableByteArray PremasterSecret) {
        this.premasterSecret = PremasterSecret;
    }

    @Override
    public void setPremasterSecret(byte[] value) {
        this.premasterSecret = ModifiableVariableFactory.safelySetValue(this.premasterSecret, value);
    }

    public ModifiableByteArray getEncryptedPremasterSecret() {
        return encryptedPremasterSecret;
    }

    public void setEncryptedPremasterSecret(ModifiableByteArray encryptedPremasterSecret) {
        this.encryptedPremasterSecret = encryptedPremasterSecret;
    }

    public void setEncryptedPremasterSecret(byte[] value) {
        this.encryptedPremasterSecret = ModifiableVariableFactory.safelySetValue(this.encryptedPremasterSecret, value);
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

    @Override
    public void setSecretsInConfig(Config config) {
        config.setDefaultPSKKey(psk.getValue());
    }
}
