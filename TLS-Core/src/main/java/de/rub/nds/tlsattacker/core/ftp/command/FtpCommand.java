/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp.command;

import de.rub.nds.tlsattacker.core.ftp.FtpCommandType;
import de.rub.nds.tlsattacker.core.ftp.FtpMessage;
import de.rub.nds.tlsattacker.core.ftp.handler.FtpCommandHandler;
import de.rub.nds.tlsattacker.core.ftp.parser.command.FtpCommandParser;
import de.rub.nds.tlsattacker.core.ftp.preparator.FtpCommandPreparator;
import de.rub.nds.tlsattacker.core.ftp.serializer.FtpCommandSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * High level representation of an FTP command according to RFC 959. FTP commands consist of a
 * single line with a keyword and optional arguments separated by a single space. They are
 * terminated with CRLF.
 */
@XmlRootElement
public class FtpCommand extends FtpMessage {

    final String keyword;
    String arguments;

    public FtpCommand(String keyword, String arguments) {
        // use for easy creation of custom commands
        this.keyword = keyword;
        this.arguments = arguments;
        this.commandType = FtpCommandType.CUSTOM;
    }

    public FtpCommand(FtpCommandType commandType, String arguments) {
        this.commandType = commandType;
        this.keyword = commandType.getKeyword();
        this.arguments = arguments;
    }

    public FtpCommand() {
        // JAXB constructor
        this("", "");
    }

    @Override
    public FtpCommandHandler<? extends FtpMessage> getHandler(Context context) {
        return new FtpCommandHandler<>(context.getFtpContext());
    }

    @Override
    public FtpCommandParser<? extends FtpMessage> getParser(Context context, InputStream stream) {
        return new FtpCommandParser<>(stream);
    }

    @Override
    public FtpCommandPreparator<? extends FtpMessage> getPreparator(Context context) {
        return new FtpCommandPreparator<>(context.getChooser(), this);
    }

    @Override
    public FtpCommandSerializer<? extends FtpMessage> getSerializer(Context context) {
        return new FtpCommandSerializer<>(this, context.getFtpContext());
    }

    @Override
    public String toShortString() {
        return "FTP_CMD";
    }

    @Override
    public String toCompactString() {
        return this.getClass().getSimpleName()
                + " ("
                + keyword
                + (arguments != null ? " " + arguments : "")
                + ")";
    }

    public String getKeyword() {
        return keyword;
    }

    public String getArguments() {
        return arguments;
    }

    public void setArguments(String arguments) {
        this.arguments = arguments;
    }

    public String serialize() {
        final String SP = " ";
        final String CRLF = "\r\n";

        StringBuilder sb = new StringBuilder();

        boolean keywordExists = this.getKeyword() != null;
        boolean argumentsExist = this.getArguments() != null;

        if (keywordExists) {
            sb.append(this.getKeyword());
        }
        if (keywordExists && argumentsExist) {
            sb.append(SP);
        }
        if (argumentsExist) {
            sb.append(this.getArguments());
        }

        sb.append(CRLF);
        return sb.toString();
    }
}
