/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.PWDServerKeyExchangeMessage;
import java.math.BigInteger;

public class PWDServerKeyExchangeHandler
        extends ServerKeyExchangeHandler<PWDServerKeyExchangeMessage> {

    public PWDServerKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(PWDServerKeyExchangeMessage message) {
        tlsContext.setSelectedGroup(NamedGroup.getNamedGroup(message.getNamedGroup().getValue()));
        tlsContext.setServerPWDSalt(message.getSalt().getValue());
        tlsContext.setServerPWDElement(
                PointFormatter.formatFromByteArray(
                        tlsContext.getChooser().getSelectedNamedGroup(),
                        message.getElement().getValue()));
        tlsContext.setServerPWDScalar(new BigInteger(1, message.getScalar().getValue()));
        if (message.getComputations() != null) {
            tlsContext.setPWDPE(message.getComputations().getPasswordElement());
            tlsContext.setServerPWDPrivate(message.getComputations().getPrivateKeyScalar());
        }
    }
}
