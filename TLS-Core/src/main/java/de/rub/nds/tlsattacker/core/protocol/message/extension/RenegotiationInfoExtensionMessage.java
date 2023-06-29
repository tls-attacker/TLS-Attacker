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
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.RenegotiationInfoExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.RenegotiationInfoExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.RenegotiationInfoExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.RenegotiationInfoExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** This extension is defined in RFC5746 */
@XmlRootElement(name = "RenegotiationInfoExtension")
public class RenegotiationInfoExtensionMessage
        extends ExtensionMessage<RenegotiationInfoExtensionMessage> {

    @ModifiableVariableProperty private ModifiableByteArray renegotiationInfo;

    @ModifiableVariableProperty private ModifiableInteger renegotiationInfoLength;

    public RenegotiationInfoExtensionMessage() {
        super(ExtensionType.RENEGOTIATION_INFO);
    }

    public ModifiableByteArray getRenegotiationInfo() {
        return renegotiationInfo;
    }

    public void setRenegotiationInfo(ModifiableByteArray renegotiationInfo) {
        this.renegotiationInfo = renegotiationInfo;
    }

    public void setRenegotiationInfo(byte[] renegotiationInfo) {
        this.renegotiationInfo =
                ModifiableVariableFactory.safelySetValue(this.renegotiationInfo, renegotiationInfo);
    }

    public ModifiableInteger getRenegotiationInfoLength() {
        return renegotiationInfoLength;
    }

    public void setRenegotiationInfoLength(ModifiableInteger renegotiationInfoLength) {
        this.renegotiationInfoLength = renegotiationInfoLength;
    }

    public void setRenegotiationInfoLength(int renegotiationInfoLength) {
        this.renegotiationInfoLength =
                ModifiableVariableFactory.safelySetValue(
                        this.renegotiationInfoLength, renegotiationInfoLength);
    }

    @Override
    public RenegotiationInfoExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new RenegotiationInfoExtensionParser(stream, tlsContext);
    }

    @Override
    public RenegotiationInfoExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new RenegotiationInfoExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public RenegotiationInfoExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new RenegotiationInfoExtensionSerializer(this);
    }

    @Override
    public RenegotiationInfoExtensionHandler getHandler(TlsContext tlsContext) {
        return new RenegotiationInfoExtensionHandler(tlsContext);
    }
}
