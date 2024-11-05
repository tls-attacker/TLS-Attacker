/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ice.model;

import de.rub.nds.tlsattacker.core.constants.stun.StunAttributeType;
import de.rub.nds.tlsattacker.core.ice.handler.UseCandidateHandler;
import de.rub.nds.tlsattacker.core.ice.parser.UseCandidateParser;
import de.rub.nds.tlsattacker.core.ice.preparator.UseCandidatePreparator;
import de.rub.nds.tlsattacker.core.ice.serializer.UseCandidateSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import java.io.InputStream;

public class UseCandidateAttribute extends StunAttribute {

    public UseCandidateAttribute() {
        super(StunAttributeType.USE_CANDIDATE);
    }

    @Override
    public UseCandidateHandler getHandler(Context context) {
        return new UseCandidateHandler(context);
    }

    @Override
    public UseCandidateParser getParser(Context context, InputStream stream) {
        return new UseCandidateParser(context, stream);
    }

    @Override
    public UseCandidatePreparator getPreparator(Context context) {
        return new UseCandidatePreparator(context.getChooser(), this);
    }

    @Override
    public UseCandidateSerializer getSerializer(Context context) {
        return new UseCandidateSerializer(this);
    }
}
