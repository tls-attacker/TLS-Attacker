/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

/** Specifies the type of the keys */
public enum Tls13KeySetType {
    NONE,
    EARLY_TRAFFIC_SECRETS,
    HANDSHAKE_TRAFFIC_SECRETS,
    APPLICATION_TRAFFIC_SECRETS;
}
