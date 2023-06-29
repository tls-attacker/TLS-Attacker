/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto.keys;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import java.security.PrivateKey;

@XmlAccessorType(XmlAccessType.FIELD)
public abstract class CustomPrivateKey implements PrivateKey {

    public abstract void adjustInContext(TlsContext tlsContext, ConnectionEndType ownerOfKey);

    public abstract void adjustInConfig(Config config, ConnectionEndType ownerOfKey);
}
