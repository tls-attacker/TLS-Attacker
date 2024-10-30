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
import de.rub.nds.tlsattacker.core.quic.handler.frame.MaxDataFrameHandler;
import de.rub.nds.tlsattacker.core.quic.parser.frame.MaxDataFrameParser;
import de.rub.nds.tlsattacker.core.quic.preparator.frame.MaxDataFramePreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.MaxDataFrameSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class MaxDataFrame extends QuicFrame {

    @ModifiableVariableProperty protected ModifiableInteger maximumData;

    private int maximumDataConfig;

    public MaxDataFrame() {
        super(QuicFrameType.MAX_DATA_FRAME);
    }

    public MaxDataFrame(int maximumDataConfig) {
        this();
        this.maximumDataConfig = maximumDataConfig;
    }

    @Override
    public MaxDataFrameHandler getHandler(Context context) {
        return new MaxDataFrameHandler(context.getQuicContext());
    }

    @Override
    public MaxDataFrameSerializer getSerializer(Context context) {
        return new MaxDataFrameSerializer(this);
    }

    @Override
    public MaxDataFramePreparator getPreparator(Context context) {
        return new MaxDataFramePreparator(context.getChooser(), this);
    }

    @Override
    public MaxDataFrameParser getParser(Context context, InputStream stream) {
        return new MaxDataFrameParser(stream);
    }

    public ModifiableInteger getMaximumData() {
        return maximumData;
    }

    public void setMaximumData(ModifiableInteger maximumData) {
        this.maximumData = maximumData;
    }

    public void setMaximumData(int maximumData) {
        this.maximumData = ModifiableVariableFactory.safelySetValue(this.maximumData, maximumData);
    }

    public int getMaximumDataConfig() {
        return maximumDataConfig;
    }

    public void setMaximumDataConfig(int maximumDataConfig) {
        this.maximumDataConfig = maximumDataConfig;
    }
}
