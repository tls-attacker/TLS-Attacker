/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKBinder;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PSKBinderParser extends Parser<PSKBinder> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PSKBinderParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(PSKBinder pskBinder) {
        LOGGER.debug("Parsing PSKBinder");
        parseBinderLength(pskBinder);
        parseBinderEntry(pskBinder);
    }

    private void parseBinderLength(PSKBinder pskBinder) {
        pskBinder.setBinderEntryLength(parseIntField(ExtensionByteLength.PSK_BINDER_LENGTH));
        LOGGER.debug("Binder length:" + pskBinder.getBinderEntryLength().getValue());
    }

    private void parseBinderEntry(PSKBinder pskBinder) {
        pskBinder.setBinderEntry(parseByteArrayField(pskBinder.getBinderEntryLength().getValue()));
        LOGGER.debug("Parsed binder: {}", pskBinder.getBinderEntry().getValue());
    }
}
