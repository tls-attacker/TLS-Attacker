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
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.tlsattacker.core.quic.constants.QuicFrameType;
import de.rub.nds.tlsattacker.core.quic.parser.frame.AckFrameParser;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * Receivers send ACK frames (types 0x02 and 0x03) to inform senders of packets they have received
 * and processed.
 */
@XmlRootElement
public class AckFrameWithEcn extends AckFrame {

    @ModifiableVariableProperty protected ModifiableLong ect0;

    @ModifiableVariableProperty protected ModifiableLong ect1;

    @ModifiableVariableProperty protected ModifiableLong ecnCe;

    public AckFrameWithEcn() {
        super(QuicFrameType.ACK_FRAME_WITH_ECN);
    }

    @Override
    public AckFrameParser getParser(QuicContext context, InputStream stream) {
        return new AckFrameParser(stream, true);
    }

    public void setEct0(long ect0) {
        this.ect0 = ModifiableVariableFactory.safelySetValue(this.ect0, ect0);
    }

    public void setEct0(int ect0) {
        this.ect0 = ModifiableVariableFactory.safelySetValue(this.ect0, (long) ect0);
    }

    public ModifiableLong getEct0() {
        return ect0;
    }

    public void setEct1(long ect1) {
        this.ect1 = ModifiableVariableFactory.safelySetValue(this.ect1, ect1);
    }

    public void setEct1(int ect1) {
        this.ect1 = ModifiableVariableFactory.safelySetValue(this.ect1, (long) ect1);
    }

    public ModifiableLong getEct1() {
        return ect1;
    }

    public void setEcnCe(long ecnCe) {
        this.ecnCe = ModifiableVariableFactory.safelySetValue(this.ecnCe, ecnCe);
    }

    public void setEcnCe(int ecnCe) {
        this.ecnCe = ModifiableVariableFactory.safelySetValue(this.ecnCe, (long) ecnCe);
    }

    public ModifiableLong getEcnCe() {
        return ecnCe;
    }
}
