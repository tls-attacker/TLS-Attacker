/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.constants;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public enum KeyExchangeAlgorithm {

    NULL,
    DHE_DSS,
    DHE_RSA,
    DHE_PSK,
    DH_ANON,
    RSA,
    DH_DSS,
    DH_RSA,
    KRB5,
    SRP,
    PSK,
    EC_DIFFIE_HELLMAN,
    GOSTR341001,
    GOSTR341094,
    CECPQ1;

}
