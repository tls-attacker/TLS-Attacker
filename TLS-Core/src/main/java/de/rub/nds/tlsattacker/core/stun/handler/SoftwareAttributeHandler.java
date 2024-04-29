/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.handler;

import de.rub.nds.tlsattacker.core.layer.context.IceContext;
import de.rub.nds.tlsattacker.core.stun.model.SoftwareAttribute;

public class SoftwareAttributeHandler extends StunAttributeHandler<SoftwareAttribute> {

    public SoftwareAttributeHandler(IceContext context) {
        super(context);
    }

    @Override
    public void adjustContext(SoftwareAttribute container) {
        if (context.getChooser().getTalkingConnectionEnd() == context.getChooser().getMyConnectionPeer()) {
            context.setPeerSoftwareString(container.getSoftwareString().getValue());
        } else {
            context.setOurSoftwareString(container.getSoftwareString().getValue());
        }
    }
}
