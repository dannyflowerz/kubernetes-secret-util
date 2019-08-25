package io.github.dannyflowerz.kubernetessecretutil;

/**
 * A wrapper for exceptions occurring while creating key stores from Kubernetes secrets
 */
public final class KeyStoreInitializationException extends RuntimeException {

    /**
     * Handles all exceptions that occur while creating key stores from Kubernetes secrets
     *
     * @param message: custom message based on exception
     * @param cause: wrapped exception
     */
    public KeyStoreInitializationException(String message, Throwable cause) {
        super(message, cause);
    }

}
