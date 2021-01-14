/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsattacker.core.crypto.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.Bits;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/**
 * TLS-AEAD-Cipher "Chacha20Poly1305", based on BouncyCastle's classes for the initial draft version See
 * draft-mavrogiannopoulos-chacha-tls-01 for further information.
 * 
 * The main differences to the standardized version are: 1. IV only consists of sequence number (instead of SQN ^ IV) 2.
 * Order of fields for MAC input (AAD length directly follows AAD bytes)
 */
public class UnofficialChaCha20Poly1305Cipher extends ChaCha20Poly1305Cipher {

    private static final Logger LOGGER = LogManager.getLogger();

    public UnofficialChaCha20Poly1305Cipher(byte[] key) {
        super(key);
        setCipher(new ChaChaEngine());
        setDraftStructure(true);
    }
}
