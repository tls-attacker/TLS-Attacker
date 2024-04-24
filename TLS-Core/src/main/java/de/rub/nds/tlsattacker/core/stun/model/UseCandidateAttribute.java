/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.model;

import de.rub.nds.tlsattacker.core.layer.context.IceContext;
import de.rub.nds.tlsattacker.core.stun.handler.UseCandidateHandler;
import de.rub.nds.tlsattacker.core.stun.parser.UseCandidateParser;
import de.rub.nds.tlsattacker.core.stun.preparator.UseCandidatePreparator;
import de.rub.nds.tlsattacker.core.stun.serializer.UseCandidateSerializer;
import java.io.InputStream;

public class UseCandidateAttribute extends StunAttribute {

    public UseCandidateAttribute() {
        super();
    }

    @Override
    public UseCandidateHandler getHandler(IceContext context) {
        return new UseCandidateHandler(context);
    }

    @Override
    public UseCandidateParser getParser(IceContext context, InputStream stream) {
        return new UseCandidateParser(context, stream);
    }

    @Override
    public UseCandidatePreparator getPreparator(IceContext context) {
        return new UseCandidatePreparator(context.getChooser(), this);
    }

    @Override
    public UseCandidateSerializer getSerializer(IceContext context) {
        return new UseCandidateSerializer(this);
    }
}
