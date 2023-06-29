/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import static de.rub.nds.modifiablevariable.util.ArrayConverter.bytesToHexString;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RenegotiationInfoExtensionParser
        extends ExtensionParser<RenegotiationInfoExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RenegotiationInfoExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(RenegotiationInfoExtensionMessage msg) {
        msg.setRenegotiationInfoLength(parseIntField(ExtensionByteLength.RENEGOTIATION_INFO));
        msg.setRenegotiationInfo(parseByteArrayField(msg.getRenegotiationInfoLength().getValue()));
        LOGGER.debug(
                "The RenegotiationInfoExtensionParser parsed the value "
                        + bytesToHexString(msg.getRenegotiationInfo()));
    }
}
