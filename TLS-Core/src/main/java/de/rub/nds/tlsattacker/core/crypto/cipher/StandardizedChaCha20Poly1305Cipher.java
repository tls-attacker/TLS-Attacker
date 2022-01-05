/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.crypto.cipher;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;

/**
 * TLS-AEAD-Cipher "Chacha20Poly1305", based on BouncyCastle's class "BcChaCha20Poly1305". See RFC7905 for further
 * information.
 */
public class StandardizedChaCha20Poly1305Cipher extends ChaCha20Poly1305Cipher {

    private static final Logger LOGGER = LogManager.getLogger();

    public StandardizedChaCha20Poly1305Cipher(byte[] key) {
        super(key, 12);
        setCipher(new ChaCha7539Engine());
        setDraftStructure(false);
    }
}
