/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2;

import static de.rub.nds.modifiablevariable.ModifiableVariableFactory.safelySetValue;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;

public class ResponderId {

    @ModifiableVariableProperty
    ModifiableInteger idLength;
    @ModifiableVariableProperty
    ModifiableByteArray id;

    Integer idLengthConfig;
    byte[] idConfig;

    public ResponderId(Integer preparatorIdLength, byte[] preparatorId) {
        this.idLengthConfig = preparatorIdLength;
        this.idConfig = preparatorId;
    }

    public ResponderId() {
    }

    public ModifiableInteger getIdLength() {
        return idLength;
    }

    public void setIdLength(ModifiableInteger idLength) {
        this.idLength = idLength;
    }

    public void setIdLength(int idLength) {
        this.idLength = safelySetValue(this.idLength, idLength);
    }

    public ModifiableByteArray getId() {
        return id;
    }

    public void setId(ModifiableByteArray id) {
        this.id = id;
    }

    public void setId(byte[] id) {
        this.id = safelySetValue(this.id, id);
    }

    public Integer getIdLengthConfig() {
        return idLengthConfig;
    }

    public void setIdLengthConfig(Integer idLengthConfig) {
        this.idLengthConfig = idLengthConfig;
    }

    public byte[] getIdConfig() {
        return idConfig;
    }

    public void setIdConfig(byte[] idConfig) {
        this.idConfig = idConfig;
    }

}
