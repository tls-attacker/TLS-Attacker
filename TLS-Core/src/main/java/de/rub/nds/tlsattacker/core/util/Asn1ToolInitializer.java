/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.asn1.parser.contentunpackers.ContentUnpackerRegister;
import de.rub.nds.asn1.parser.contentunpackers.DefaultContentUnpacker;
import de.rub.nds.asn1.parser.contentunpackers.PrimitiveBitStringUnpacker;
import de.rub.nds.asn1.translator.ContextRegister;
import de.rub.nds.asn1.translator.ParseNativeTypesContext;
import de.rub.nds.asn1.translator.ParseOcspTypesContext;

public class Asn1ToolInitializer {

    static boolean alreadyInitialized = false;

    public static void initAsn1Tool() {
        if (!alreadyInitialized) {
            registerContexts();
            registerContentUnpackers();
            alreadyInitialized = true;
        }
    }

    private static void registerContexts() {
        ContextRegister contextRegister = ContextRegister.getInstance();
        contextRegister.registerContext(ParseNativeTypesContext.NAME, ParseNativeTypesContext.class);
        contextRegister.registerContext(ParseOcspTypesContext.NAME, ParseOcspTypesContext.class);
    }

    private static void registerContentUnpackers() {
        ContentUnpackerRegister contentUnpackerRegister = ContentUnpackerRegister.getInstance();
        contentUnpackerRegister.registerContentUnpacker(new DefaultContentUnpacker());
        contentUnpackerRegister.registerContentUnpacker(new PrimitiveBitStringUnpacker());
    }
}
