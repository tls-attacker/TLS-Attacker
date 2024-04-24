/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.parser;

import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.stun.IceContext;
import de.rub.nds.tlsattacker.core.stun.model.ErrorCodeAttribute;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
public class ErrorCodeAttributeParser extends StunAttributeParser<ErrorCodeAttribute> {

    public ErrorCodeAttributeParser(IceContext context, InputStream stream) {
        super(context, stream);
    }

    @Override
    public void parse(ErrorCodeAttribute attribute) {
        attribute.setReservedByte(
                parseByteArrayField(IceByteLengths.STUN_ERROR_CODE_RESERVED_BYTES));
        attribute.setErrorCodeClass(parseByteArrayField(IceByteLengths.STUN_ERROR_CLASS));
        attribute.setErrorCodeLowerValue(parseByteArrayField(IceByteLengths.STUN_ERROR_VALUE));
        attribute.setReasonPhrase(new String(parseTillEnd(), StandardCharsets.UTF_8));
        int errorCode = attribute.getErrorCodeClass().getValue()[0] * 100 + attribute.getErrorCodeLowerValue().getValue()[0];
        attribute.setNumber(errorCode);
    }
}
