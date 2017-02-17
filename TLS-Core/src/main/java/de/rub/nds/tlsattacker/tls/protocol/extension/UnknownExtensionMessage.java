/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.extension;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class UnknownExtensionMessage extends ExtensionMessage {

    public UnknownExtensionMessage(TlsConfig tlsConfig) {
        super();
        this.extensionTypeConstant = ExtensionType.UNKNOWN;

    }

    public UnknownExtensionMessage() {
        super();
        this.extensionTypeConstant = ExtensionType.UNKNOWN;
    }

    @Override
    public ExtensionHandler<? extends ExtensionMessage> getExtensionHandler() {
        return new UnknownExtensionHandler();
    }
}
