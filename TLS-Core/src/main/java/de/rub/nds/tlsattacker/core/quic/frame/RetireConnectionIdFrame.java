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
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.quic.constants.QuicFrameType;
import de.rub.nds.tlsattacker.core.quic.handler.frame.RetireConnectionIdFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.RetireConnectionIdFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.RetireConnectionIdFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.RetireConnectionIdFrameSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class RetireConnectionIdFrame extends QuicFrame {

    @ModifiableVariableProperty protected ModifiableInteger sequenceNumber;

    private int sequenceNumberConfig;

    public RetireConnectionIdFrame() {
        super(QuicFrameType.RETIRE_CONNECTION_ID);
    }

    public RetireConnectionIdFrame(int sequenceNumberConfig) {
        this();
        this.sequenceNumberConfig = sequenceNumberConfig;
    }

    @Override
    public RetireConnectionIdFrameHandler getHandler(Context context) {
        return new RetireConnectionIdFrameHandler(context.getQuicContext());
    }

    @Override
    public RetireConnectionIdFrameSerializer getSerializer(Context context) {
        return new RetireConnectionIdFrameSerializer(this);
    }

    @Override
    public RetireConnectionIdFramePreparator getPreparator(Context context) {
        return new RetireConnectionIdFramePreparator(context.getChooser(), this);
    }

    @Override
    public RetireConnectionIdFrameParser getParser(Context context, InputStream stream) {
        return new RetireConnectionIdFrameParser(stream);
    }

    public ModifiableInteger getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(ModifiableInteger sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    public void setSequenceNumber(int sequenceNumber) {
        this.sequenceNumber =
                ModifiableVariableFactory.safelySetValue(this.sequenceNumber, sequenceNumber);
    }

    public int getSequenceNumberConfig() {
        return sequenceNumberConfig;
    }

    public void setSequenceNumberConfig(int sequenceNumberConfig) {
        this.sequenceNumberConfig = sequenceNumberConfig;
    }
}
