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
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.config.Config;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PSKPremasterComputations extends KeyExchangeComputations {

    private static final Logger LOGGER = LogManager.getLogger();

    private ModifiableByteArray premasterSecret;

    private ModifiableByteArray psk;

    public PSKPremasterComputations() {
    }

    public PSKPremasterComputations(ModifiableByteArray psk) {
        this.psk = psk;
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

    @Override
    public void setSecretsInConfig(Config config) {
        if (psk != null && psk.getValue() != null) {
            config.setDefaultPSKKey(psk.getValue());
        } else {
            LOGGER.warn("Could not adjust PSK to config. PSK is null");
        }
    }
}
