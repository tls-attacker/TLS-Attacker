package de.rub.nds.tlsattacker.core.protocol.parser.context;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;

@SuppressWarnings("serial")
public class ParserContextParserException extends ParserException {

	private final ParserContext currentContext;
	
	private final ParserContext previousContext;

	public ParserContextParserException(String message, ParserContext currentContext, ParserContext previousContext) {
		super(message);
		this.currentContext = currentContext;
		this.previousContext = previousContext;
	}

	public ParserContext getCurrentContext() {
		return currentContext;
	}

	public ParserContext getPreviousContext() {
		return previousContext;
	}
}
