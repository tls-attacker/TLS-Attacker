/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.ECDHClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import java.math.BigInteger;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;

public class ECDHClientKeyExchangeHandlerTest {

    private ECDHClientKeyExchangeHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        context = new TlsContext();
        handler = new ECDHClientKeyExchangeHandler(context);

    }

    @After
    public void tearDown() {
    }

    /**
     * Test of adjustContext method, of class ECDHClientKeyExchangeHandler.
     */
    @SuppressWarnings("SpellCheckingInspection")
    @Test
    public void testadjustContext() {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256);
        context.setClientRandom(new byte[] {});
        context.setServerRandom(new byte[] {});
        // set server ECDH-parameters
        context.getConfig().setDefaultSelectedNamedGroup(NamedGroup.SECP192R1);
        context.setSelectedGroup(NamedGroup.SECP192R1);
        context.setServerEcPublicKey(
            Point.createPoint(new BigInteger("1336698681267683560144780033483217462176613397209956026562"),
                new BigInteger("4390496211885670837594012513791855863576256216444143941964"), NamedGroup.SECP192R1));
        context.getConfig().setDefaultClientEcPrivateKey(new BigInteger("3"));
        context.getConfig().setDefaultServerEcPrivateKey(new BigInteger("3"));
        ECDHClientKeyExchangeMessage message = new ECDHClientKeyExchangeMessage(context.getConfig());
        ECDHClientKeyExchangePreparator prep = new ECDHClientKeyExchangePreparator(context.getChooser(), message);
        prep.prepare();
        handler.adjustContext(message);
        assertArrayEquals(ArrayConverter.hexStringToByteArray("273CF78A3DB2E37EE97935DEF45E3C82F126807C31A498E9"),
            context.getPreMasterSecret());
        assertArrayEquals(
            ArrayConverter.hexStringToByteArray(
                "5686D5F789AEDC43162480112E94C7C60F1292B1C5D688AE58F237BD054594775B94AC5F0B18A01B808ADBBE78BCC8C7"),
            context.getMasterSecret());

    }
}
