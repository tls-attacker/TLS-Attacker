/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.protocol.message.PWDServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import java.math.BigInteger;

public class PWDServerKeyExchangeHandler extends ServerKeyExchangeHandler<PWDServerKeyExchangeMessage> {

    public PWDServerKeyExchangeHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustContext(PWDServerKeyExchangeMessage message) {
        context.setSelectedGroup(NamedGroup.getNamedGroup(message.getNamedGroup().getValue()));
        context.setServerPWDSalt(message.getSalt().getValue());
        context.setServerPWDElement(PointFormatter.formatFromByteArray(context.getChooser().getSelectedNamedGroup(),
            message.getElement().getValue()));
        context.setServerPWDScalar(new BigInteger(1, message.getScalar().getValue()));
        if (message.getComputations() != null) {
            context.setPWDPE(message.getComputations().getPasswordElement());
            context.setServerPWDPrivate(message.getComputations().getPrivateKeyScalar());
        }
    }
}
