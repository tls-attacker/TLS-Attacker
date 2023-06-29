/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.CachedInfoExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CachedInfoExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.CachedInfoExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CachedInfoExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

/** RFC7924 */
@XmlRootElement(name = "CachedInfoExtension")
public class CachedInfoExtensionMessage extends ExtensionMessage<CachedInfoExtensionMessage> {

    @ModifiableVariableProperty private ModifiableInteger cachedInfoLength;
    @HoldsModifiableVariable private List<CachedObject> cachedInfo;

    @ModifiableVariableProperty private ModifiableByteArray cachedInfoBytes;

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
        this.cachedInfoLength =
                ModifiableVariableFactory.safelySetValue(this.cachedInfoLength, cachedInfoLength);
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
        this.cachedInfoBytes =
                ModifiableVariableFactory.safelySetValue(this.cachedInfoBytes, cachedInfoBytes);
    }

    @Override
    public CachedInfoExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new CachedInfoExtensionParser(stream, tlsContext);
    }

    @Override
    public CachedInfoExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new CachedInfoExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public CachedInfoExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new CachedInfoExtensionSerializer(this);
    }

    @Override
    public CachedInfoExtensionHandler getHandler(TlsContext tlsContext) {
        return new CachedInfoExtensionHandler(tlsContext);
    }
}
