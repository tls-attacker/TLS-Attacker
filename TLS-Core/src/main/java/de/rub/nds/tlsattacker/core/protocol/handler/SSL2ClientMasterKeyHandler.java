/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientMasterKeyMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;

public class SSL2ClientMasterKeyHandler extends HandshakeMessageHandler<SSL2ClientMasterKeyMessage> {

    public SSL2ClientMasterKeyHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustContext(SSL2ClientMasterKeyMessage message) {
        byte[] premasterSecret = message.getComputations().getPremasterSecret().getValue();
        context.setPreMasterSecret(premasterSecret);
        context.setClearKey(message.getClearKeyData().getValue());
        if (context.getChooser().getSSL2CipherSuite().getBlockSize() != 0) {
            context.setSSL2Iv(message.getKeyArgData().getValue());
        }
    }

}
