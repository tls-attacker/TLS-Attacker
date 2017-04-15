/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler.extension;

import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.EllipticCurvesExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.EllipticCurvesExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.EllipticCurvesExtensionSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class EllipticCurvesExtensionHandler extends ExtensionHandler<EllipticCurvesExtensionMessage> {

    public EllipticCurvesExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSContext(EllipticCurvesExtensionMessage message) {
        byte[] curveBytes = message.getSupportedCurves().getValue();
        if (curveBytes.length % NamedCurve.LENGTH != 0) {
            throw new AdjustmentException("Could not create resonable NamedCurves from CurveBytes");
        }
        List<NamedCurve> curveList = new LinkedList<>();
        for (int i = 0; i < curveBytes.length; i = i + NamedCurve.LENGTH) {
            byte[] curve = Arrays.copyOfRange(curveBytes, i, i + NamedCurve.LENGTH);
            NamedCurve namedCurve = NamedCurve.getNamedCurve(curve);
            if (namedCurve == null) {
                LOGGER.warn("Unknown EllipticCruve:" + ArrayConverter.bytesToHexString(curve));
            } else {
                curveList.add(namedCurve);
            }
        }

        context.setClientNamedCurvesList(curveList);
    }

    @Override
    public EllipticCurvesExtensionParser getParser(byte[] message, int pointer) {
        return new EllipticCurvesExtensionParser(pointer, message);
    }

    @Override
    public EllipticCurvesExtensionPreparator getPreparator(EllipticCurvesExtensionMessage message) {
        return new EllipticCurvesExtensionPreparator(context, message);
    }

    @Override
    public EllipticCurvesExtensionSerializer getSerializer(EllipticCurvesExtensionMessage message) {
        return new EllipticCurvesExtensionSerializer(message);
    }

}
