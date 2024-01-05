/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http.header.preparator;

import de.rub.nds.tlsattacker.core.http.header.TokenBindingHeader;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.tokenbinding.TokenBindingMessagePreparator;
import de.rub.nds.tlsattacker.core.tokenbinding.TokenBindingMessageSerializer;
import java.util.Base64;

public class TokenBindingHeaderPreparator extends Preparator<TokenBindingHeader> {

    private final TokenBindingHeader header;

    public TokenBindingHeaderPreparator(HttpContext httpContext, TokenBindingHeader header) {
        super(httpContext.getChooser(), header);
        this.header = header;
    }

    @Override
    public void prepare() {
        header.setHeaderName("Sec-Token-Binding");
        TokenBindingMessagePreparator preparator =
                new TokenBindingMessagePreparator(chooser, header.getMessage());
        preparator.prepare();
        TokenBindingMessageSerializer serializer =
                new TokenBindingMessageSerializer(header.getMessage());
        String encodedTokenBinding =
                Base64.getUrlEncoder().withoutPadding().encodeToString(serializer.serialize());
        header.setHeaderValue(encodedTokenBinding);
    }
}
