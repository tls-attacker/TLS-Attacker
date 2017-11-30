/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TrustedCaIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.trustedauthority.TrustedAuthority;
import java.util.LinkedList;
import java.util.List;

public class TrustedCaIndicationExtensionParser extends ExtensionParser<TrustedCaIndicationExtensionMessage> {

    public TrustedCaIndicationExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(TrustedCaIndicationExtensionMessage msg) {
        msg.setTrustedAuthoritiesLength(parseIntField(ExtensionByteLength.TRUSTED_AUTHORITY_LIST_LENGTH));
        msg.setTrustedAuthoritiesBytes(parseByteArrayField(msg.getTrustedAuthoritiesLength().getValue()));

        List<TrustedAuthority> trustedAuthoritiesList = new LinkedList<>();
        int position = 0;

        while (position < msg.getTrustedAuthoritiesLength().getValue()) {
            TrustedAuthorityParser parser = new TrustedAuthorityParser(position, msg.getTrustedAuthoritiesBytes()
                    .getValue());
            trustedAuthoritiesList.add(parser.parse());
            if (position == parser.getPointer()) {
                throw new ParserException("Ran into infinite Loop while parsing TrustedAuthorities");
            }
            position = parser.getPointer();
        }
        msg.setTrustedAuthorities(trustedAuthoritiesList);
    }

    @Override
    protected TrustedCaIndicationExtensionMessage createExtensionMessage() {
        return new TrustedCaIndicationExtensionMessage();
    }

}
