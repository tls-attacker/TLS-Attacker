/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ice.handler;

import de.rub.nds.tlsattacker.core.ice.model.XorPeerAddressAttribute;
import de.rub.nds.tlsattacker.core.state.Context;

public class XorPeerAddressAttributeHandler extends StunAttributeHandler<XorPeerAddressAttribute> {

    public XorPeerAddressAttributeHandler(Context context) {
        super(context);
    }

    @Override
    public void adjustContext(XorPeerAddressAttribute container) {
        context.getIceContext().setAddress(container.getIpAddress().getValue());
        context.getIceContext().setPort(container.getPort().getValue());
    }
}
