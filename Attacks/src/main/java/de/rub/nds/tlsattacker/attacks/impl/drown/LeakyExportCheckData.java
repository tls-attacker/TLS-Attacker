/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.impl.drown;

import de.rub.nds.tlsattacker.core.constants.SSL2CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientMasterKeyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerVerifyMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.Serializable;

/**
 * Container storing data required for LeakyExportCheckCallable. The primary feature of this is being serializable.
 */
public class LeakyExportCheckData implements Serializable {

    private byte[] clearKey;
    private byte[] secretKeyPlain;
    private byte[] secretKeyEnc;
    private byte[] clientRandom;
    private byte[] serverRandom;
    private byte[] iv;
    private SSL2CipherSuite cipherSuite;
    private byte[] encrypted;
    private int paddingLength;

    LeakyExportCheckData(TlsContext context, SSL2ClientMasterKeyMessage clientMessage,
        SSL2ServerVerifyMessage serverMessage) {
        clearKey = context.getClearKey();
        // The Premaster Secret is equivalent to SECRET-KEY-DATA
        secretKeyPlain = context.getPreMasterSecret();
        secretKeyEnc = clientMessage.getEncryptedKeyData().getValue();
        clientRandom = context.getClientRandom();
        serverRandom = context.getServerRandom();
        iv = context.getSSL2Iv();
        cipherSuite = context.getChooser().getSSL2CipherSuite();
        encrypted = serverMessage.getEncryptedPart().getValue();
        paddingLength = serverMessage.getPaddingLength().getValue();
    }

    public byte[] getClearKey() {
        return clearKey;
    }

    public byte[] getSecretKeyPlain() {
        return secretKeyPlain;
    }

    public byte[] getSecretKeyEnc() {
        return secretKeyEnc;
    }

    public byte[] getClientRandom() {
        return clientRandom;
    }

    public byte[] getServerRandom() {
        return serverRandom;
    }

    public byte[] getIv() {
        return iv;
    }

    public SSL2CipherSuite getCipherSuite() {
        return cipherSuite;
    }

    public byte[] getEncrypted() {
        return encrypted;
    }

    public int getPaddingLength() {
        return paddingLength;
    }

}
