/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension.keyshare;

import de.rub.nds.tlsattacker.core.constants.Bits;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.DragonFlyKeyShareEntry;
import java.io.InputStream;
import java.math.BigInteger;

public class DragonFlyKeyShareEntryParser extends Parser<DragonFlyKeyShareEntry> {

    private NamedGroup group;

    public DragonFlyKeyShareEntryParser(InputStream stream, NamedGroup group) {
        super(stream);
        this.group = group;
    }

    @Override
    public void parse(DragonFlyKeyShareEntry keyShare) {
        if (group.isCurve()) {
            EllipticCurve curve = CurveFactory.getCurve(group);
            int elementLength = curve.getModulus().bitLength();
            byte[] rawPublicKey = parseByteArrayField(elementLength * 2 / Bits.IN_A_BYTE);
            int scalarLength = parseIntField(ExtensionByteLength.PWD_SCALAR);
            BigInteger scalar = parseBigIntField(scalarLength);
            keyShare.setRawPublicKey(rawPublicKey);
            keyShare.setScalar(scalar);
            keyShare.setScalarLength(scalarLength);
        } else {
            throw new UnsupportedOperationException("Non-Curves are currently not supported");
        }
    }
}
