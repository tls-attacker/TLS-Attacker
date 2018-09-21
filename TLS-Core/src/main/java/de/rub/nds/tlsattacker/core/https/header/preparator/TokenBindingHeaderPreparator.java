/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.https.header.preparator;

import de.rub.nds.tlsattacker.core.https.header.TokenBindingHeader;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.tokenbinding.TokenBindingMessagePreparator;
import de.rub.nds.tlsattacker.core.tokenbinding.TokenBindingMessageSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.util.Base64;

public class TokenBindingHeaderPreparator extends Preparator<TokenBindingHeader> {

    private final TokenBindingHeader header;

    public TokenBindingHeaderPreparator(Chooser chooser, TokenBindingHeader header) {
        super(chooser, header);
        this.header = header;
    }

    @Override
    public void prepare() {
        header.setHeaderName("Sec-Token-Binding");
        TokenBindingMessagePreparator preparator = new TokenBindingMessagePreparator(chooser, header.getMessage());
        preparator.prepare();
        TokenBindingMessageSerializer serializer = new TokenBindingMessageSerializer(header.getMessage(),
                chooser.getSelectedProtocolVersion());
        String encodedTokenBinding = Base64.getUrlEncoder().withoutPadding().encodeToString(serializer.serialize());
        header.setHeaderValue(encodedTokenBinding);
    }

}
