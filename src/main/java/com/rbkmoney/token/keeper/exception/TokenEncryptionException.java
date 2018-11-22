package com.rbkmoney.token.keeper.exception;

public class TokenEncryptionException extends RuntimeException {

    public TokenEncryptionException() {
    }

    public TokenEncryptionException(String message) {
        super(message);
    }

    public TokenEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }

    public TokenEncryptionException(Throwable cause) {
        super(cause);
    }

    public TokenEncryptionException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
