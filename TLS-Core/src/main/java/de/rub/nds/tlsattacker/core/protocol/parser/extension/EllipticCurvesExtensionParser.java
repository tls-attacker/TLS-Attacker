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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EllipticCurvesExtensionParser extends ExtensionParser<EllipticCurvesExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EllipticCurvesExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(EllipticCurvesExtensionMessage msg) {
        LOGGER.debug("Parsing EllipticCurvesExtensionMessage");
        parseSupportedGroupsLength(msg);
        parseSupportedGroups(msg);
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
    private void parseSupportedGroupsLength(EllipticCurvesExtensionMessage msg) {
        msg.setSupportedGroupsLength(parseIntField(ExtensionByteLength.SUPPORTED_GROUPS));
        LOGGER.debug("SupportedGroupsLength: " + msg.getSupportedGroupsLength().getValue());
    }

    /**
     * Reads the next bytes as the SupportedCurves of the Extension and writes
     * them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSupportedGroups(EllipticCurvesExtensionMessage msg) {
        msg.setSupportedGroups(parseByteArrayField(msg.getSupportedGroupsLength().getValue()));
        LOGGER.debug("SupportedGroups: " + ArrayConverter.bytesToHexString(msg.getSupportedGroups().getValue()));
    }

}
