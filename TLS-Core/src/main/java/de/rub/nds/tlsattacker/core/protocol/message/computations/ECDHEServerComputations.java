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
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.core.config.Config;

public class ECDHEServerComputations extends KeyExchangeComputations {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByte ecPointFormat;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray namedGroup;

    public ECDHEServerComputations() {
    }

    public ModifiableByte getEcPointFormat() {
        return ecPointFormat;
    }

    public void setEcPointFormat(ModifiableByte format) {
        this.ecPointFormat = format;
    }

    public void setEcPointFormat(byte format) {
        this.ecPointFormat = ModifiableVariableFactory.safelySetValue(this.ecPointFormat, format);
    }

    public ModifiableByteArray getNamedGroup() {
        return this.namedGroup;
    }

    public void setNamedGroup(ModifiableByteArray namedGroup) {
        this.namedGroup = namedGroup;
    }

    public void setNamedGroup(byte[] namedGroup) {
        this.namedGroup = ModifiableVariableFactory.safelySetValue(this.namedGroup, namedGroup);
    }

    @Override
    public void setSecretsInConfig(Config config) {
        config.setDefaultServerEcPrivateKey(getPrivateKey().getValue());
    }
}
