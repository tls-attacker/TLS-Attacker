/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.preparator;

import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.stun.model.ErrorCodeAttribute;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class ErrorCodeAttributePreparator extends StunAttributePreparator<ErrorCodeAttribute> {

    public ErrorCodeAttributePreparator(Chooser chooser, ErrorCodeAttribute attribute) {
        super(chooser, attribute);
    }

    @Override
    public void prepareContent() {
        ErrorCodeAttribute attribute = getObject();
        attribute.setReservedByte(new byte[IceByteLengths.STUN_ERROR_CODE_RESERVED_BYTES]);

        Integer errorCode;
        if (attribute.getErrorCodeConfig() != null) {
            errorCode = attribute.getErrorCodeConfig();
        } else {
            errorCode = chooser.getIceChooser().getConfig().getDefaultErrorCode();
        }
        attribute.setNumber(errorCode);
        attribute.setErrorCodeClass(new byte[] {(byte) (attribute.getNumber().getValue() / 100)});
        attribute.setErrorCodeLowerValue(
                new byte[] {(byte) (attribute.getNumber().getValue() % 100)});

        String errorReason;
        if (attribute.getReasonConfig() != null) {
            errorReason = attribute.getReasonConfig();
        } else {
            errorReason = chooser.getIceChooser().getConfig().getDefaultErrorReason();
        }
        attribute.setReasonPhrase(errorReason);
    }
}
