/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun;

import de.rub.nds.tlsattacker.core.layer.context.LayerContext;
import de.rub.nds.tlsattacker.core.state.Context;

public class IceContext extends LayerContext {

    private String username;

    public IceContext(Context context) {
        super(context);
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
}
