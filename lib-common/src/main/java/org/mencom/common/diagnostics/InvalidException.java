package org.mencom.common.diagnostics;

import java.util.List;

public class InvalidException extends RuntimeException {

    private final List<String> details;
    private final String action;

    public InvalidException(String message, String action, List<String> details) {
        super(message);
        this.action = action;
        this.details = List.copyOf(details);
    }

    public List<String> getDetails() {
        return details;
    }

    public String getAction() {
        return action;
    }
}



