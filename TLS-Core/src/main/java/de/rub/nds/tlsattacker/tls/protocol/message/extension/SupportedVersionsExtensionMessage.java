/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message.extension;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.handler.extension.SupportedVersionsExtensionHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 * @author Nurullah Erinola
 */
public class SupportedVersionsExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger supportedVersionsLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray supportedVersions;
    
    public SupportedVersionsExtensionMessage() {
        super(ExtensionType.SUPPORTED_VERSIONS);
    }

    public ModifiableInteger getSupportedVersionsLength() {
        return supportedVersionsLength;
    }

    public void setSupportedVersionsLength(int length) {
        this.supportedVersionsLength = ModifiableVariableFactory.safelySetValue(this.supportedVersionsLength, length);
    }
    
    public void setSupportedVersionsLength(ModifiableInteger supportedVersionsLength) {
        this.supportedVersionsLength = supportedVersionsLength;
    }
    
    public ModifiableByteArray getSupportedVersions() {
        return supportedVersions;
    }

    public void setSupportedVersions(byte[] array) {
        this.supportedVersions = ModifiableVariableFactory.safelySetValue(this.supportedVersions, array);
    }

    public void setSupportedVersions(ModifiableByteArray supportedVersions) {
        this.supportedVersions = supportedVersions;
    }

    @Override
    public SupportedVersionsExtensionHandler getHandler(TlsContext context) {
        return new SupportedVersionsExtensionHandler(context);
    }
}
