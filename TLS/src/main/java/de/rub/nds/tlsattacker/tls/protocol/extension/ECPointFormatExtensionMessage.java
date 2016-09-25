/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.extension;

import java.util.List;

import javax.xml.bind.annotation.XmlRootElement;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.tls.constants.ECPointFormat;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
@XmlRootElement
public class ECPointFormatExtensionMessage extends ExtensionMessage {

    private List<ECPointFormat> pointFormatsConfig;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger pointFormatsLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray pointFormats;

    public ECPointFormatExtensionMessage() {
	this.extensionTypeConstant = ExtensionType.EC_POINT_FORMATS;
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
    public ExtensionHandler<? extends ExtensionMessage> getExtensionHandler() {
	return ECPointFormatExtensionHandler.getInstance();
    }

    public List<ECPointFormat> getPointFormatsConfig() {
	return pointFormatsConfig;
    }

    public void setPointFormatsConfig(List<ECPointFormat> pointFormatsConfig) {
	this.pointFormatsConfig = pointFormatsConfig;
    }

}
