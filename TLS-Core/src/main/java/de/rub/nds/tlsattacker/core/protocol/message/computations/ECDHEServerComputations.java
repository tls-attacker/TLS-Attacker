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

public class ECDHEServerComputations extends KeyExchangeComputations {

    // List of EC point formats supported by both server and clinet (or a server
    // enforced list)
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray ecPointFormatList;

    // List of available curves negotiated between server and client (or a
    // server enforced list)
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray namedGroupList;

    // TODO: serverRandom might be better placed in KeyExchangeComputations.
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    protected ModifiableByteArray serverRandom;

    public ECDHEServerComputations() {
    }

    public ModifiableByteArray getEcPointFormatList() {
        return ecPointFormatList;
    }

    public void setEcPointFormatList(ModifiableByteArray formats) {
        this.ecPointFormatList = formats;
    }

    public void setEcPointFormatList(byte[] formats) {
        this.ecPointFormatList = ModifiableVariableFactory.safelySetValue(this.ecPointFormatList, formats);
    }

    public ModifiableByteArray getNamedGroupList() {
        return this.namedGroupList;
    }

    public void setNamedGroupList(ModifiableByteArray groups) {
        this.namedGroupList = groups;
    }

    public void setNamedGroupList(byte[] groups) {
        this.namedGroupList = ModifiableVariableFactory.safelySetValue(this.namedGroupList, groups);
    }

    public ModifiableByteArray getServerRandom() {
        return serverRandom;
    }

    public void setServerRandom(ModifiableByteArray random) {
        this.serverRandom = random;
    }

    public void setServerRandom(byte[] random) {
        this.serverRandom = ModifiableVariableFactory.safelySetValue(this.serverRandom, random);
    }

    @Override
    public void setSecretsInConfig(Config config) {
        config.setDefaultServerEcPrivateKey(getPrivateKey().getValue());
    }
}
