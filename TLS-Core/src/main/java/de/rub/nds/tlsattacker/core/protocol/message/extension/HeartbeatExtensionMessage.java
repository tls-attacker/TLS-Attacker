/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.HeartbeatExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.HeartbeatExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.HeartbeatExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.HeartbeatExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** This extension is defined in RFC6520 */
@XmlRootElement(name = "HeartbeatExtension")
public class HeartbeatExtensionMessage extends ExtensionMessage<HeartbeatExtensionMessage> {

    private HeartbeatMode heartbeatModeConfig;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray heartbeatMode;

    public HeartbeatExtensionMessage() {
        super(ExtensionType.HEARTBEAT);
    }

    public ModifiableByteArray getHeartbeatMode() {
        return heartbeatMode;
    }

    public void setHeartbeatMode(ModifiableByteArray heartbeatMode) {
        this.heartbeatMode = heartbeatMode;
    }

    public void setHeartbeatMode(byte[] heartbeatMode) {
        this.heartbeatMode =
                ModifiableVariableFactory.safelySetValue(this.heartbeatMode, heartbeatMode);
    }

    public HeartbeatMode getHeartbeatModeConfig() {
        return heartbeatModeConfig;
    }

    public void setHeartbeatModeConfig(HeartbeatMode heartbeatModeConfig) {
        this.heartbeatModeConfig = heartbeatModeConfig;
    }

    @Override
    public HeartbeatExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new HeartbeatExtensionParser(stream, tlsContext);
    }

    @Override
    public HeartbeatExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new HeartbeatExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public HeartbeatExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new HeartbeatExtensionSerializer(this);
    }

    @Override
    public HeartbeatExtensionHandler getHandler(TlsContext tlsContext) {
        return new HeartbeatExtensionHandler(tlsContext);
    }
}
