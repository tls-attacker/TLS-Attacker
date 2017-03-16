/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.EllipticCurvesExtensionMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class EllipticCurvesExtensionParser extends ExtensionParser<EllipticCurvesExtensionMessage> {

    public EllipticCurvesExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(EllipticCurvesExtensionMessage msg) {
        msg.setSupportedCurvesLength(parseIntField(ExtensionByteLength.SUPPORTED_ELLIPTIC_CURVES_LENGTH));
        msg.setSupportedCurves(parseByteArrayField(msg.getSupportedCurvesLength().getValue()));
    }

    @Override
    protected EllipticCurvesExtensionMessage createExtensionMessage() {
        return new EllipticCurvesExtensionMessage();
    }

}
