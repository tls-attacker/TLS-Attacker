/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun;

import de.rub.nds.tlsattacker.core.layer.context.IceContext;

public class IceChooser {

    private final IceConfig config;

    private final IceContext context;

    public IceChooser(IceConfig config, IceContext context) {
        this.config = config;
        this.context = context;
    }

    public IceConfig getConfig() {
        return config;
    }

    public IceContext getContext() {
        return context;
    }

    public byte[] getAddress() {
        if (context.getAddress() == null) {
            return config.getDefaultAddress();
        } else {
            return context.getAddress();
        }
    }

    public Integer getPort() {
        if (context.getPort() == null) {
            return config.getDefaultPort();
        } else {
            return context.getPort();
        }
    }

    public byte[] getStunTransactionId() {
        if (context.getStunTransactionId() == null) {
            return config.getDefaultStunTransactionId();
        } else {
            return context.getStunTransactionId();
        }
    }
}
