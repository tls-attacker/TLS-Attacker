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

public class ClientEncryptedSni extends ModifiableVariableHolder implements Serializable {

    /* Non-ModifiableVariables: */
    private byte[] clientEsniInnerBytes;

    /* TODO Add ModifiableVariables for: */
    // CipherSuite suite;
    // KeyShareEntry key_share;
    // opaque record_digest<0..2^16-1>;
    // opaque encrypted_sni<0..2^16-1>
    // ClientESNIInner

    public byte[] getClientEsniInnerBytes() {
        return clientEsniInnerBytes;
    }

    public void setClientEsniInnerBytes(byte[] clientEsniInnerBytes) {
        this.clientEsniInnerBytes = clientEsniInnerBytes;
    }

}
