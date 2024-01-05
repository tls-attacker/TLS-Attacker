/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.compressor.compression;

import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class CompressionAlgorithm {

    protected static final Logger LOGGER = LogManager.getLogger();
    private final CompressionMethod method;

    public CompressionAlgorithm(CompressionMethod method) {
        this.method = method;
    }

    public abstract byte[] compress(byte[] data);

    public abstract byte[] decompress(byte[] data);
}
