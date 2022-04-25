package com.vc.volunteeringcommunity.auth.security;

import com.vc.volunteeringcommunity.auth.model.User;

import javax.naming.AuthenticationException;

public interface UserContextService {
    User getLoggedInUser() throws AuthenticationException;
}
