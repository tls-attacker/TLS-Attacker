/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.constant;

/**
 * Pre-defined configurations for the Layer Stack. E.g., DTLS would add the UDP-, Record-,
 * Fragmentation-, and Message- Layer to the LayerStack. Custom LayerStack have to be created
 * manually.
 */
public enum LayerConfiguration {
    TLS,
    DTLS,
    QUIC,
    OPEN_VPN,

    STARTTLS,
    HTTPS,
    SSL2;
}
