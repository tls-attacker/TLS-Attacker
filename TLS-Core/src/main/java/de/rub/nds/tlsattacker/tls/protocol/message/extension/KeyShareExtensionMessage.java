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
import de.rub.nds.tlsattacker.tls.protocol.handler.extension.KeyShareExtensionHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 * @author Nurullah Erinola
 */
public class KeyShareExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray keyShareEntrys;

    public KeyShareExtensionMessage() {
        super(ExtensionType.KEY_SHARE);
    }
    
    public ModifiableByteArray getKeyShareEntrys() {
        return keyShareEntrys;
    }

    public void setKeyShareEntrys(byte[] array) {
        this.keyShareEntrys = ModifiableVariableFactory.safelySetValue(this.keyShareEntrys, array);
    }
    
    public void setKeyShareEntrys(ModifiableByteArray keyShareEntrys) {
        this.keyShareEntrys = keyShareEntrys;
    }
    
    @Override
    public KeyShareExtensionHandler getHandler(TlsContext context) {
        return new KeyShareExtensionHandler(context);
    }
    
}
