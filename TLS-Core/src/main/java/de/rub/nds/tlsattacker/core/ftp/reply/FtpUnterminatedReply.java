/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp.reply;

import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.ftp.parser.reply.FtpReplyParser;
import de.rub.nds.tlsattacker.core.state.Context;
import java.io.InputStream;

public class FtpUnterminatedReply extends FtpUnknownReply {

    @Override
    public FtpReplyParser<? extends FtpReply> getParser(Context context, InputStream stream) {
        return new FtpReplyParser<FtpUnterminatedReply>(stream) {
            @Override
            public void parse(FtpUnterminatedReply reply) {
                try {
                    this.parseTillEnd();
                } catch (Exception e) {
                    throw new ParserException(
                            "FtpUnterminatedReply emptied stream and raised an exception", e);
                }
            }
        };
    }
}
