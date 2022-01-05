/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message.certificatestatus;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;

public class CertificateStatusObject {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger type;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger length;

    @ModifiableVariableProperty
    private ModifiableByteArray ocspResponse;

    public ModifiableInteger getType() {
        return type;
    }

    public void setType(ModifiableInteger type) {
        this.type = type;
    }

    public void setType(int type) {
        this.type = ModifiableVariableFactory.safelySetValue(this.type, type);
    }

    public ModifiableInteger getLength() {
        return length;
    }

    public void setLength(ModifiableInteger length) {
        this.length = length;
    }

    public void setLength(int length) {
        this.length = ModifiableVariableFactory.safelySetValue(this.length, length);
    }

    public ModifiableByteArray getOcspResponse() {
        return ocspResponse;
    }

    public void setOcspResponse(ModifiableByteArray ocspResponse) {
        this.ocspResponse = ocspResponse;
    }

    public void setOcspResponse(byte[] ocspResponse) {
        this.ocspResponse = ModifiableVariableFactory.safelySetValue(this.ocspResponse, ocspResponse);
    }

}
