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
import de.rub.nds.modifiablevariable.mlong.ModifiableLong;
import de.rub.nds.tlsattacker.core.quic.constants.QuicFrameType;
import de.rub.nds.tlsattacker.core.quic.handler.frame.NewTokenFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.NewTokenFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.NewTokenFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.NewTokenFrameSerializer;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class NewTokenFrame extends QuicFrame<NewTokenFrame> {

    /** A variable-length integer specifying the length of the token in bytes. */
    @ModifiableVariableProperty protected ModifiableLong tokenLength;

    /**
     * An opaque blob that the client can use with a future Initial packet. The token MUST NOT be
     * empty. A client MUST treat receipt of a NEW_TOKEN frame with an empty Token field as a
     * connection error of type FRAME_ENCODING_ERROR.
     */
    @ModifiableVariableProperty protected ModifiableByteArray token;

    public NewTokenFrame() {
        super(QuicFrameType.NEW_TOKEN_FRAME);
    }

    @Override
    public NewTokenFrameHandler getHandler(QuicContext context) {
        return new NewTokenFrameHandler(context);
    }

    @Override
    public NewTokenFrameSerializer getSerializer(QuicContext context) {
        return new NewTokenFrameSerializer(this);
    }

    @Override
    public NewTokenFramePreparator getPreparator(QuicContext context) {
        return new NewTokenFramePreparator(context.getChooser(), this);
    }

    @Override
    public NewTokenFrameParser getParser(QuicContext context, InputStream stream) {
        return new NewTokenFrameParser(stream);
    }

    public ModifiableLong getTokenLength() {
        return tokenLength;
    }

    public void setTokenLength(long tokenLength) {
        this.tokenLength = ModifiableVariableFactory.safelySetValue(this.tokenLength, tokenLength);
    }

    public void setTokenLength(int tokenLength) {
        this.setTokenLength((long) tokenLength);
    }

    public ModifiableByteArray getToken() {
        return token;
    }

    public void setToken(byte[] token) {
        this.token = ModifiableVariableFactory.safelySetValue(this.token, token);
    }
}
