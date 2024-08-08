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

@XmlRootElement
public class AckFrameWithEcn extends AckFrame {

    /**
     * A variable-length integer representing the total number of packets received with the ECT(0)
     * codepoint in the packet number space of the ACK frame.
     */
    @ModifiableVariableProperty protected ModifiableLong ect0;

    /**
     * A variable-length integer representing the total number of packets received with the ECT(1)
     * codepoint in the packet number space of the ACK frame.
     */
    @ModifiableVariableProperty protected ModifiableLong ect1;

    /**
     * A variable-length integer representing the total number of packets received with the ECN-CE
     * codepoint in the packet number space of the ACK frame.
     */
    @ModifiableVariableProperty protected ModifiableLong ecnCe;

    public AckFrameWithEcn() {
        super(QuicFrameType.ACK_FRAME_WITH_ECN);
    }

    public void setEct0(long ect0) {
        this.ect0 = ModifiableVariableFactory.safelySetValue(this.ect0, ect0);
    }

    public ModifiableLong getEct0() {
        return ect0;
    }

    public void setEct1(long ect1) {
        this.ect1 = ModifiableVariableFactory.safelySetValue(this.ect1, ect1);
    }

    public ModifiableLong getEct1() {
        return ect1;
    }

    public void setEcnCe(long ecnCe) {
        this.ecnCe = ModifiableVariableFactory.safelySetValue(this.ecnCe, ecnCe);
    }

    public ModifiableLong getEcnCe() {
        return ecnCe;
    }

    @Override
    public AckFrameParser getParser(QuicContext context, InputStream stream) {
        return new AckFrameParser(stream, true);
    }
}
