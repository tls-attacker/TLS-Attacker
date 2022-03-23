/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TrustedCaIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.trustedauthority.TrustedAuthority;
import de.rub.nds.tlsattacker.core.state.TlsContext;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

public class TrustedCaIndicationExtensionParser extends ExtensionParser<TrustedCaIndicationExtensionMessage> {

    public TrustedCaIndicationExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parseExtensionMessageContent(TrustedCaIndicationExtensionMessage msg) {
        msg.setTrustedAuthoritiesLength(parseIntField(ExtensionByteLength.TRUSTED_AUTHORITY_LIST_LENGTH));
        msg.setTrustedAuthoritiesBytes(parseByteArrayField(msg.getTrustedAuthoritiesLength().getValue()));

        List<TrustedAuthority> trustedAuthoritiesList = new LinkedList<>();
        ByteArrayInputStream innerStream = new ByteArrayInputStream(msg.getTrustedAuthoritiesBytes().getValue());

        while (innerStream.available() > 0) {
            TrustedAuthorityParser parser = new TrustedAuthorityParser(innerStream);
            TrustedAuthority authority = new TrustedAuthority();
            parser.parse(authority);
            trustedAuthoritiesList.add(authority);
        }
        msg.setTrustedAuthorities(trustedAuthoritiesList);
    }
}
