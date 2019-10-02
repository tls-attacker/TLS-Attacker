/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.computations;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.math.BigInteger;
import static org.junit.Assert.*;
import org.junit.Test;

public class PWDComputationsTest {

    @Test
    public void computePE() throws CryptoException {
        TlsContext context = new TlsContext();
        context.setSelectedCipherSuite(CipherSuite.TLS_ECCPWD_WITH_AES_128_GCM_SHA256);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setClientRandom(ArrayConverter
                .hexStringToByteArray("528fbf52175de2c869845fdbfa8344f7d732712ebfa679d8643cd31a880e043d"));
        context.setServerRandom(ArrayConverter
                .hexStringToByteArray("528fbf524378a1b13b8d2cbd247090721369f8bfa3ceeb3cfcd85cbfcdd58eaa"));
        context.setClientPWDUsername("fred");
        context.getConfig().setDefaultPWDPassword("barney");
        EllipticCurve curve = CurveFactory.getCurve(NamedGroup.BRAINPOOLP256R1);
        Point passwordElement = PWDComputations.computePasswordElement(context.getChooser(), curve);
        BigInteger expectedX = new BigInteger("686B0D3FC49894DD621EC04F925E029B2B1528EDEDCA46007254281E9A6EDC", 16);
        assertArrayEquals(ArrayConverter.bigIntegerToByteArray(expectedX),
                ArrayConverter.bigIntegerToByteArray(passwordElement.getX().getData()));

        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        passwordElement = PWDComputations.computePasswordElement(context.getChooser(), curve);
        expectedX = new BigInteger("0BA387CE8123BEA05A4327520F5A2A66B038F2024F239F330038DA0A2744F79B", 16);
        assertArrayEquals(ArrayConverter.bigIntegerToByteArray(expectedX),
                ArrayConverter.bigIntegerToByteArray(passwordElement.getX().getData()));
    }

}
