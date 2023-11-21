/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.frame;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.quic.constants.QuicFrameType;
import de.rub.nds.tlsattacker.core.quic.handler.frame.PathChallengeFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.PathChallengeFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.PathChallengeFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.PathChallengeFrameSerializer;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * Endpoints can use PATH_CHALLENGE frames (type=0x1a) to check reachability to the peer and for
 * path validation during connection migration.
 */
@XmlRootElement
public class PathChallengeFrame extends QuicFrame<PathChallengeFrame> {

    @ModifiableVariableProperty protected ModifiableByteArray data;

    public PathChallengeFrame() {
        super(QuicFrameType.PATH_CHALLENGE_FRAME);
    }

    @Override
    public PathChallengeFrameHandler getHandler(QuicContext context) {
        return new PathChallengeFrameHandler(context);
    }

    @Override
    public PathChallengeFrameSerializer getSerializer(QuicContext context) {
        return new PathChallengeFrameSerializer(this);
    }

    @Override
    public PathChallengeFramePreparator getPreparator(QuicContext context) {
        return new PathChallengeFramePreparator(context.getChooser(), this);
    }

    @Override
    public PathChallengeFrameParser getParser(QuicContext context, InputStream stream) {
        return new PathChallengeFrameParser(stream);
    }

    public ModifiableByteArray getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
    }
}
