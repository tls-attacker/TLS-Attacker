/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.preparator;

import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpVRFYReply;
import java.util.ArrayList;
import java.util.List;

public class VRFYReplyPreparator extends SmtpReplyPreparator<SmtpVRFYReply> {
    public VRFYReplyPreparator(SmtpContext context, SmtpVRFYReply reply) {
        super(context.getChooser(), reply);
    }

    @Override
    public void prepare() {
        getObject().setReplyCode(getObject().getReplyCode());
        getObject().setReplyLines(createReplyLines());
    }

    private List<String> createReplyLines() {
        List<String> replyLines = new ArrayList<>();

        if (is250Response()) {
            replyLines.add(getFullNameAndMailboxString(0, !getObject().getFullNames().isEmpty()));
            return replyLines;
        }

        if (isDescriptionOnlyResponse()) {
            replyLines.add(getObject().getDescription());
            return replyLines;
        }

        if (isDescriptionAndMailboxResponse()) {
            replyLines.add(getObject().getDescription() + " " + getObject().getMailboxes().get(0));
            return replyLines;
        }

        if (is553Response()) {
            boolean fullNamesExist = !getObject().getFullNames().isEmpty();
            boolean sizesDoNotMatch =
                    getObject().getMailboxes().size() != getObject().getFullNames().size();

            if (fullNamesExist && sizesDoNotMatch)
                throw new PreparationException(
                        "VRFY-Reply's fullNames and mailboxes sizes do not match.");

            if (getObject().getDescription() != null) replyLines.add(getObject().getDescription());

            for (int i = 0; i < getObject().getMailboxes().size(); i++) {
                replyLines.add(getFullNameAndMailboxString(i, fullNamesExist));
            }

            return replyLines;
        }

        throw new PreparationException(
                "Malformed VRFY-Reply: Reply cannot be matched with any valid replies.");
    }

    private String getFullNameAndMailboxString(int index, boolean containsFullNames) {
        StringBuilder sb = new StringBuilder();

        if (containsFullNames) {
            sb.append(getObject().getFullNames().get(index));
            sb.append(" ");
        }

        sb.append(getObject().getMailboxes().get(index));

        return sb.toString();
    }

    private boolean is250Response() {
        return getObject().getDescription() == null
                && getObject().getMailboxes().size() == 1
                && getObject().getFullNames().size() <= 1;
    }

    private boolean isDescriptionOnlyResponse() {
        return getObject().getDescription() != null
                && getObject().getFullNames().isEmpty()
                && getObject().getMailboxes().isEmpty();
    }

    private boolean isDescriptionAndMailboxResponse() {
        return getObject().getDescription() != null
                && getObject().getMailboxes().size() == 1
                && getObject().getFullNames().isEmpty();
    }

    private boolean is553Response() {
        return getObject().getDescription() != null
                        && getObject().getMailboxes().isEmpty()
                        && getObject().getFullNames().isEmpty()
                || getObject().getMailboxes().size() > 1;
    }
}
