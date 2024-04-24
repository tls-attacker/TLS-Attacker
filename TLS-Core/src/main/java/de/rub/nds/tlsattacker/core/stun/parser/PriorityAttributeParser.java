/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.stun.IceContext;
import de.rub.nds.tlsattacker.core.stun.model.PriorityAttribute;
import java.io.InputStream;

public class PriorityAttributeParser extends StunAttributeParser<PriorityAttribute> {

    public PriorityAttributeParser(IceContext context, InputStream stream) {
        super(context, stream);
    }

    @Override
    public void parse(PriorityAttribute attribute) {
        attribute.setPriority(
                ArrayConverter.bytesToLong(
                        parseByteArrayField(IceByteLengths.STUN_PRIORITY_LENGTH)));
    }
}
