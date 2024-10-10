/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.command;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.*;
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpCommandHandler;
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpMessageHandler;
import de.rub.nds.tlsattacker.core.smtp.parser.SmtpMessageParser;
import de.rub.nds.tlsattacker.core.smtp.parser.command.SmtpCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.command.SmtpCommandPreparator;
import de.rub.nds.tlsattacker.core.smtp.serializer.SmtpCommandSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.bouncycastle.math.raw.Mod;

import java.io.InputStream;

@XmlRootElement(name = "SmtpCommand")
public class SmtpCommand extends SmtpMessage {

    @ModifiableVariableProperty
    ModifiableString verb;
    // this field is used by preparator+serializer for the command parameters, it should not be used
    // for the actual contents
    @ModifiableVariableProperty
    ModifiableString parameters;

    public SmtpCommand(String verb, String parameters) {
        super();
        this.verb = ModifiableVariableFactory.safelySetValue(this.verb, verb);
        this.parameters = ModifiableVariableFactory.safelySetValue(this.parameters, parameters);
    }

    public SmtpCommand(String verb) {
        this.verb = ModifiableVariableFactory.safelySetValue(this.verb, verb);
        this.parameters = new ModifiableString();
    }

    public SmtpCommand() {
        this.verb = new ModifiableString();
        this.parameters = new ModifiableString();
    }

    @Override
    public SmtpCommandHandler<? extends SmtpCommand> getHandler(SmtpContext smtpContext) {
        return new SmtpCommandHandler<>(smtpContext);
    }

    @Override
    public SmtpCommandParser<? extends SmtpCommand> getParser(
            SmtpContext context, InputStream stream) {
        return new SmtpCommandParser<>(stream);
    }

    @Override
    public SmtpCommandPreparator<? extends SmtpCommand> getPreparator(SmtpContext context) {
        return new SmtpCommandPreparator<>(context.getChooser(), this);
    }

    @Override
    public SmtpCommandSerializer<? extends SmtpCommand> getSerializer(SmtpContext context) {
        return new SmtpCommandSerializer<>(context, this);
    }

    @Override
    public String toShortString() {
        return "SMTP_CMD";
    }

    @Override
    public String toCompactString() {
        return "SMTPCommand";
    }

    public ModifiableString getVerb() {
        return verb;
    }

    public void setVerb(String verb) {
        this.verb = ModifiableVariableFactory.safelySetValue(this.verb, verb);
    }

    public ModifiableString getParameters() {
        return parameters;
    }

    public void setParameters(String parameters) {
        this.parameters = ModifiableVariableFactory.safelySetValue(this.parameters, parameters);
    }
}
