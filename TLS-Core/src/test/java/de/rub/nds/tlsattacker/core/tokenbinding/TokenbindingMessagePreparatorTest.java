/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.tokenbinding;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ChooserType;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.core.workflow.chooser.ChooserFactory;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class TokenbindingMessagePreparatorTest {

    private TlsContext context;

    private Config config;

    private Chooser chooser;

    private TokenBindingMessage message;

    private TokenbindingMessagePreparator preparator;

    @Before
    public void setUp() {
        config = Config.createConfig();
        context = new TlsContext(config);
        chooser = ChooserFactory.getChooser(ChooserType.DEFAULT, context);
        message = new TokenBindingMessage();
        preparator = new TokenbindingMessagePreparator(chooser, message);
        config.setDefaultSelectedSignatureAndHashAlgorithm(new SignatureAndHashAlgorithm(SignatureAlgorithm.ECDSA,
                HashAlgorithm.SHA1));
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Test of prepareProtocolMessageContents method, of class
     * TokenbindingMessagePreparator.
     */
    @Test
    public void testPrepareProtocolMessageContents() {
        preparator.prepare();
    }

}
