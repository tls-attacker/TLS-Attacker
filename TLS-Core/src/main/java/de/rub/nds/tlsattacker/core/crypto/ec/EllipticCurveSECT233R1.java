/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto.ec;

import java.math.BigInteger;

@SuppressWarnings("SpellCheckingInspection")
public class EllipticCurveSECT233R1 extends EllipticCurveOverF2m {
    public EllipticCurveSECT233R1() {
        super(
                BigInteger.ONE,
                new BigInteger("0066647EDE6C332C7F8C0923BB58213B333B20E9CE4281FE115F7D8F90AD", 16),
                new BigInteger("20000000000000000000000000000000000000004000000000000000001", 16),
                new BigInteger("00FAC9DFCBAC8313BB2139F1BB755FEF65BC391F8B36F8F8EB7371FD558B", 16),
                new BigInteger("01006A08A41903350678E58528BEBF8A0BEFF867A7CA36716F7E01F81052", 16),
                new BigInteger("01000000000000000000000000000013E974E72F8A6922031D2603CFE0D7", 16));
    }
}
