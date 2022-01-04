/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * RFC7924
 */
@XmlRootElement(name = "CachedInfoExtension")
public class CachedInfoExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty
    private ModifiableInteger cachedInfoLength;
    @HoldsModifiableVariable
    private List<CachedObject> cachedInfo;

    @ModifiableVariableProperty
    private ModifiableByteArray cachedInfoBytes;

    public CachedInfoExtensionMessage() {
        super(ExtensionType.CACHED_INFO);
        cachedInfo = new LinkedList<>();
    }

    public CachedInfoExtensionMessage(Config config) {
        super(ExtensionType.CACHED_INFO);
        cachedInfo = new LinkedList<>();
        cachedInfo.addAll(config.getCachedObjectList());
    }

    public ModifiableInteger getCachedInfoLength() {
        return cachedInfoLength;
    }

    public void setCachedInfoLength(ModifiableInteger cachedInfoLength) {
        this.cachedInfoLength = cachedInfoLength;
    }

    public void setCachedInfoLength(int cachedInfoLength) {
        this.cachedInfoLength = ModifiableVariableFactory.safelySetValue(this.cachedInfoLength, cachedInfoLength);
    }

    public List<CachedObject> getCachedInfo() {
        return cachedInfo;
    }

    public void setCachedInfo(List<CachedObject> cachedInfo) {
        this.cachedInfo = cachedInfo;
    }

    public ModifiableByteArray getCachedInfoBytes() {
        return cachedInfoBytes;
    }

    public void setCachedInfoBytes(ModifiableByteArray cachedInfoBytes) {
        this.cachedInfoBytes = cachedInfoBytes;
    }

    public void setCachedInfoBytes(byte[] cachedInfoBytes) {
        this.cachedInfoBytes = ModifiableVariableFactory.safelySetValue(this.cachedInfoBytes, cachedInfoBytes);
    }

}
