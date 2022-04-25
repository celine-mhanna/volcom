package com.vc.volunteeringcommunity.auth.security;

import javax.naming.AuthenticationException;

public class NoLoggedInUserException extends AuthenticationException {
    NoLoggedInUserException() {
    }
}
