package com.vc.volunteeringcommunity.auth.security.services;

import com.vc.volunteeringcommunity.auth.model.User;
import com.vc.volunteeringcommunity.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;

@Service

public class LoginHistoryServiceImpl implements LoginHistoryService{

    @Autowired
    private UserRepository userRepository;

    @Value("${volcom.db.login-history-keep-seconds:31536000}")
    private int loginHistorySecondsToKeep;

    @Override
    public void addLoginRecord(String username, HttpServletRequest req){
        User loggedInUser = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Non existent user successfully logged in"));
    }
    
}
