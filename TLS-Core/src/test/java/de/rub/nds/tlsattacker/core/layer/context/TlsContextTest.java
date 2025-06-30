/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.context;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.SSL2CipherSuite;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TlsContextTest {

    private TlsContext tlsContext;
    private Context context;

    @BeforeEach
    void setUp() {
        Config config = new Config();
        State state = new State(config);
        context = new Context(state, new InboundConnection());
        tlsContext = context.getTlsContext();
    }

    @Test
    void testSelectedCipherSuiteInitiallyNull() {
        assertNull(tlsContext.getSelectedCipherSuite());
    }

    @Test
    void testSetAndGetSelectedCipherSuite() {
        CipherSuite cipherSuite = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA;
        tlsContext.setSelectedCipherSuite(cipherSuite);
        assertEquals(cipherSuite, tlsContext.getSelectedCipherSuite());
    }

    @Test
    void testSsl2CipherSuiteInitiallyNull() {
        assertNull(tlsContext.getSSL2CipherSuite());
    }

    @Test
    void testSetAndGetSsl2CipherSuite() {
        SSL2CipherSuite ssl2CipherSuite = SSL2CipherSuite.SSL_CK_RC4_128_WITH_MD5;
        tlsContext.setSSL2CipherSuite(ssl2CipherSuite);
        assertEquals(ssl2CipherSuite, tlsContext.getSSL2CipherSuite());
    }
}
