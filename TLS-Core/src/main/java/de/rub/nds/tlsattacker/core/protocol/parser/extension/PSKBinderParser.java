/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKBinder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

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
        LOGGER.debug("Parsed binder:" + ArrayConverter.bytesToHexString(pskBinder.getBinderEntry().getValue()));
    }

}
