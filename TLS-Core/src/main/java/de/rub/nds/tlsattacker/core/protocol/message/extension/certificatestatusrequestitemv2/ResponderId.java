/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.certificatestatusrequestitemv2;

import static de.rub.nds.modifiablevariable.ModifiableVariableFactory.safelySetValue;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class ResponderId {

    @ModifiableVariableProperty
    ModifiableInteger idLength;
    @ModifiableVariableProperty
    ModifiableByteArray id;
    
    public ResponderId(int idLength, byte[] id) {
        this.idLength = safelySetValue(this.idLength, idLength);
        this.id = safelySetValue(this.id, id);
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
}
