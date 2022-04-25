package com.vc.volunteeringcommunity.auth.security.services;

public interface UserAuthenticationService {

    void resetUserPassword(String username, String oldPassword, String newPassword);

}
