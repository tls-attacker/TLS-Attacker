/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;

/**
 *

 */
public class EllipticCurvesExtensionParser extends ExtensionParser<EllipticCurvesExtensionMessage> {

    public EllipticCurvesExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(EllipticCurvesExtensionMessage msg) {
        LOGGER.debug("Parsing EllipticCurvesExtensionMessage");
        parseSupportedCurvesLength(msg);
        parseSupportedCurves(msg);
    }

    @Override
    protected EllipticCurvesExtensionMessage createExtensionMessage() {
        return new EllipticCurvesExtensionMessage();
    }

    /**
     * Reads the next bytes as the SupportedCurvesLength of the Extension and
     * writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSupportedCurvesLength(EllipticCurvesExtensionMessage msg) {
        msg.setSupportedCurvesLength(parseIntField(ExtensionByteLength.SUPPORTED_ELLIPTIC_CURVES));
        LOGGER.debug("SupportedCurvesLength: " + msg.getSupportedCurvesLength().getValue());
    }

    /**
     * Reads the next bytes as the SupportedCurves of the Extension and writes
     * them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSupportedCurves(EllipticCurvesExtensionMessage msg) {
        msg.setSupportedCurves(parseByteArrayField(msg.getSupportedCurvesLength().getValue()));
        LOGGER.debug("SupportedCurves: " + ArrayConverter.bytesToHexString(msg.getSupportedCurves().getValue()));
    }

}
