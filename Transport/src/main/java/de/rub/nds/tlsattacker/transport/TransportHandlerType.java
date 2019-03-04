/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport;

public enum TransportHandlerType {

    TCP,
    EAP_TLS,
    UDP,
    NON_BLOCKING_TCP,
    STREAM,
    TCP_TIMING,
    UDP_TIMING,
    TCP_PROXY_TIMING,
    TCP_NO_DELAY,

}
