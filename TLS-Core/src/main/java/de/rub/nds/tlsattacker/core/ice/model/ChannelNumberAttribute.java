/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ice.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.stun.StunAttributeType;
import de.rub.nds.tlsattacker.core.ice.handler.ChannelNumberAttributeHandler;
import de.rub.nds.tlsattacker.core.ice.parser.ChannelNumberAttributeParser;
import de.rub.nds.tlsattacker.core.ice.preparator.ChannelNumberAttributePreparator;
import de.rub.nds.tlsattacker.core.ice.serializer.ChannelNumberAttributeSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import java.io.InputStream;

/**
 * CHANNEL-NUMBER attribute as defined in RFC 5766 (TURN), Section 14.1.
 *
 * <p>Value: 4 bytes - Channel Number: 2 bytes (0x4000-0x7FFF) - RFFU: 2 bytes (Reserved For Future
 * Use, must be set to 0 on transmission and ignored on reception)
 */
public class ChannelNumberAttribute extends StunAttribute {

    private Integer channelNumberConfig = null;

    /** 2 bytes unsigned */
    private ModifiableInteger channelNumber;

    /** 2 bytes RFFU (typically zero) */
    private ModifiableInteger rffu;

    public ChannelNumberAttribute() {
        super(StunAttributeType.CHANNEL_NUMBER);
    }

    public Integer getChannelNumberConfig() {
        return channelNumberConfig;
    }

    public void setChannelNumberConfig(Integer channelNumberConfig) {
        this.channelNumberConfig = channelNumberConfig;
    }

    public ModifiableInteger getChannelNumber() {
        return channelNumber;
    }

    public void setChannelNumber(ModifiableInteger channelNumber) {
        this.channelNumber = channelNumber;
    }

    public void setChannelNumber(int channelNumber) {
        this.channelNumber =
                ModifiableVariableFactory.safelySetValue(this.channelNumber, channelNumber);
    }

    public ModifiableInteger getRffu() {
        return rffu;
    }

    public void setRffu(ModifiableInteger rffu) {
        this.rffu = rffu;
    }

    public void setRffu(int rffu) {
        this.rffu = ModifiableVariableFactory.safelySetValue(this.rffu, rffu);
    }

    @Override
    public ChannelNumberAttributeParser getParser(Context context, InputStream stream) {
        return new ChannelNumberAttributeParser(context, stream);
    }

    @Override
    public ChannelNumberAttributePreparator getPreparator(Context context) {
        return new ChannelNumberAttributePreparator(context.getChooser(), this);
    }

    @Override
    public ChannelNumberAttributeSerializer getSerializer(Context context) {
        return new ChannelNumberAttributeSerializer(this);
    }

    @Override
    public ChannelNumberAttributeHandler getHandler(Context context) {
        return new ChannelNumberAttributeHandler(context);
    }
}
