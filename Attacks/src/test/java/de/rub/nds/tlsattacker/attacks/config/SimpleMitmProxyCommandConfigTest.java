/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.config;

import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import java.io.InputStream;
import org.junit.Test;

/**
 *
 *
 */
public class SimpleMitmProxyCommandConfigTest {

    private SimpleMitmProxyCommandConfig cmdConfig;
    private InputStream inputKeyStream;

    /**
     *
     */
    public SimpleMitmProxyCommandConfigTest() {
        cmdConfig = new SimpleMitmProxyCommandConfig(new GeneralDelegate());
    }

    /**
     *
     */
    @Test
    public void testLoadPrivateKeyRsaWithPassword() {
    }

    /**
     *
     */
    @Test
    public void testLoadPrivateKeyEc() {
    }

    /**
     *
     */
    @Test
    public void testLoadPrivateKeyEcWithPassword() {
    }

    /**
     *
     */
    @Test
    public void testLoadPrivateKeyDh() {
    }

    /**
     *
     */
    @Test
    public void testLoadPrivateKeyDhWithPassword() {
    }

}
