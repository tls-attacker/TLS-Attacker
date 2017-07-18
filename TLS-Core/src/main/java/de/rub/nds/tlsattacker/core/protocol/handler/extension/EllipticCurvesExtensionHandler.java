/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EllipticCurvesExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EllipticCurvesExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EllipticCurvesExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * This handler processes the EllipticCurves extensions, as defined in
 * https://tools.ietf.org/search/rfc4492#section-5.1.1
 * 
 * But in TLS 1.3 this extensions renamed to SupportedGroups. See:
 * https://tools.ietf.org/html/draft-ietf-tls-tls13-21#section-4.2.6
 * 
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
        for (int i = 0; i < curveBytes.length; i += NamedCurve.LENGTH) {
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
