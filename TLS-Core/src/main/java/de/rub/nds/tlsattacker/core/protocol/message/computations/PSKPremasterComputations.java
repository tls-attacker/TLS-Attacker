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
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PSKPremasterComputations extends KeyExchangeComputations {

    private static final Logger LOGGER = LogManager.getLogger();

    private ModifiableByteArray premasterSecret;

    private ModifiableByteArray psk;

    public PSKPremasterComputations() {}

    public PSKPremasterComputations(ModifiableByteArray psk) {
        this.psk = psk;
    }

    @Override
    public ModifiableByteArray getPremasterSecret() {
        return premasterSecret;
    }

    @Override
    public void setPremasterSecret(ModifiableByteArray premasterSecret) {
        this.premasterSecret = premasterSecret;
    }

    @Override
    public void setPremasterSecret(byte[] value) {
        this.premasterSecret =
                ModifiableVariableFactory.safelySetValue(this.premasterSecret, value);
    }
}
