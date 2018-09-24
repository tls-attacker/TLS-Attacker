/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
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
