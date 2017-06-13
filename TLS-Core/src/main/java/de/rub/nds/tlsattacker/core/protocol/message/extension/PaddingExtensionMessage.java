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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.PaddingExtensionHandler;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class PaddingExtensionMessage extends ExtensionMessage {

    /**
     * Contains the padding bytes of the padding extension. The bytes shall be
     * empty.
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.NONE)
    private ModifiableByteArray paddingBytes;

    public ModifiableByteArray getPaddingBytes() {
        return paddingBytes;
    }

    public void setPaddingBytes(ModifiableByteArray paddingBytes) {
        this.paddingBytes = paddingBytes;
    }

    public void setPaddingBytes(byte[] array) {
        this.paddingBytes = ModifiableVariableFactory.safelySetValue(paddingBytes, array);
    }

    public PaddingExtensionMessage() {
        super(ExtensionType.PADDING);
    }

    @Override
    public PaddingExtensionHandler getHandler(TlsContext context) {
        return new PaddingExtensionHandler(context);
    }

}
