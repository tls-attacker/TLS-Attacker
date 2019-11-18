/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension.keyshare;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.DragonFlyKeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;
import java.math.BigInteger;

public class DragonFlyKeyShareEntryParser extends Parser<DragonFlyKeyShareEntry> {

    private NamedGroup group;

    public DragonFlyKeyShareEntryParser(byte[] array, NamedGroup group) {
        super(0, array);
        this.group = group;
    }

    @Override
    public DragonFlyKeyShareEntry parse() {
        if (group.isCurve()) {
            EllipticCurve curve = CurveFactory.getCurve(group);
            int elementLength = curve.getModulus().bitLength();
            System.out.println(elementLength);
            byte[] rawPublicKey = parseByteArrayField(elementLength * 2 / 8);
            int scalarLength = parseIntField(ExtensionByteLength.PWD_SCALAR);
            BigInteger scalar = parseBigIntField(scalarLength);
            return new DragonFlyKeyShareEntry(rawPublicKey, scalarLength, scalar);
        } else {
            throw new UnsupportedOperationException("Non-Curves are currently not supported");
        }
    }

}
