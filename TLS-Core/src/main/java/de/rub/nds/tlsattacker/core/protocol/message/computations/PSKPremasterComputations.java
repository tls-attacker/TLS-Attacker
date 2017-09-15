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
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PSKPremasterComputations extends KeyExchangeComputations {

    @ModifiableVariableProperty(format = ModifiableVariableProperty.Format.PKCS1, type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    private ModifiableByteArray PremasterSecret;

    private ModifiableByteArray psk;
    private ModifiableInteger psklength;

    public PSKPremasterComputations() {
    }

    public PSKPremasterComputations(ModifiableInteger psklength, ModifiableByteArray psk) {
        this.psklength = psklength;
        this.psk = psk;
    }

    @Override
    public ModifiableByteArray getPremasterSecret() {
        return PremasterSecret;
    }

    @Override
    public void setPremasterSecret(ModifiableByteArray PremasterSecret) {
        this.PremasterSecret = PremasterSecret;
    }

    @Override
    public void setPremasterSecret(byte[] value) {
        this.PremasterSecret = ModifiableVariableFactory.safelySetValue(this.PremasterSecret, value);
    }
}
