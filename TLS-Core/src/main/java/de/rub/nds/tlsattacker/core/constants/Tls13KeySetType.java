/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsattacker.core.constants;

/**
 * Specifies the type of the keys
 */
public enum Tls13KeySetType {
    NONE,
    EARLY_TRAFFIC_SECRETS,
    HANDSHAKE_TRAFFIC_SECRETS,
    APPLICATION_TRAFFIC_SECRETS;
}
