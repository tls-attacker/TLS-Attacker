/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ECPointFormatExtensionHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
@XmlRootElement
public class ECPointFormatExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger pointFormatsLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray pointFormats;

    public ECPointFormatExtensionMessage() {
        super(ExtensionType.EC_POINT_FORMATS);
    }

    public ModifiableByteArray getPointFormats() {
        return pointFormats;
    }

    public void setPointFormats(byte[] array) {
        this.pointFormats = ModifiableVariableFactory.safelySetValue(pointFormats, array);
    }

    public ModifiableInteger getPointFormatsLength() {
        return pointFormatsLength;
    }

    public void setPointFormatsLength(int length) {
        this.pointFormatsLength = ModifiableVariableFactory.safelySetValue(pointFormatsLength, length);
    }

    public void setPointFormatsLength(ModifiableInteger pointFormatsLength) {
        this.pointFormatsLength = pointFormatsLength;
    }

    public void setPointFormats(ModifiableByteArray pointFormats) {
        this.pointFormats = pointFormats;
    }

    @Override
    public ECPointFormatExtensionHandler getHandler(TlsContext context) {
        return new ECPointFormatExtensionHandler(context);
    }
}
