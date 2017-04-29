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
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.extension.PaddingExtensionHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

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
    public ExtensionHandler getHandler(TlsContext context) {
        return new PaddingExtensionHandler(context);
    }

}
