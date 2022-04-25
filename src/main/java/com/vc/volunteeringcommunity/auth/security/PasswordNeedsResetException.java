package com.vc.volunteeringcommunity.auth.security;

public class PasswordNeedsResetException extends Exception {

    public PasswordNeedsResetException(String msg) {
        super(msg);
    }

}
