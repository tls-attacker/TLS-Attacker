/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport;

public enum TransportHandlerType {
    TCP,
    EAP_TLS,
    UDP,
    STREAM,
    TCP_TIMING,
    UDP_TIMING,
    UDP_PROXY,
    TCP_PROXY_TIMING,
    TCP_NO_DELAY,
    TCP_FRAGMENTATION
}
