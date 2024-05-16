/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ice.handler;

import de.rub.nds.tlsattacker.core.ice.model.XorMappedAddressAttribute;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;

public class XorMappedAddressAttributeHandler
        extends StunAttributeHandler<XorMappedAddressAttribute> {

    public XorMappedAddressAttributeHandler(IceContext context) {
        super(context);
    }

    @Override
    public void adjustContext(XorMappedAddressAttribute container) {
        context.setAddress(container.getIpAddress().getValue());
        context.setPort(container.getPort().getValue());
    }
}
