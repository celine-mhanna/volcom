package com.vc.volunteeringcommunity.auth.security.services;

import javax.servlet.http.HttpServletRequest;

public interface LoginHistoryService {

    void addLoginRecord(String username, HttpServletRequest req);
    
}
