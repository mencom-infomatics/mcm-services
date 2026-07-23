package org.mencom.common.diagnostics;

import org.jspecify.annotations.NonNull;
import org.springframework.boot.diagnostics.AbstractFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;

public class MCMFailureAnalyzer extends AbstractFailureAnalyzer<InvalidException> {

    @Override
    protected FailureAnalysis analyze(@NonNull Throwable rootFailure, @NonNull InvalidException cause) {
        String description = cause.getMessage();
        if (!cause.getDetails().isEmpty()) {
            description = description + " Details: " + String.join(", ", cause.getDetails()) + ".";
        }
        String action = cause.getAction() == null ? "Review the invalid configuration and try again." : cause.getAction();
        return new FailureAnalysis(description, action, cause);
    }
}


