/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.esni;

import java.io.Serializable;

import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;

public class ClientEsniInner extends ModifiableVariableHolder implements Serializable {

    /* Non-ModifiableVariables: */
    private byte[] serverNameListBytes;

    /* TODO Add ModifiableVariables for: */
    // uint8 nonce[16];
    // PaddedServerNameList realSNI;

    public byte[] getServerNameListBytes() {
        return serverNameListBytes;
    }

    public void setServerNameListBytes(byte[] serverNameListBytes) {
        this.serverNameListBytes = serverNameListBytes;
    }

}