package com.vc.volunteeringcommunity.auth.security;

import com.vc.volunteeringcommunity.auth.model.User;
import com.vc.volunteeringcommunity.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.naming.AuthenticationException;
import java.util.Optional;

@Component
public class SpringUserContextService implements UserContextService {
    @Autowired
    UserRepository userRepository;

    private String getCurrentUsername() throws AuthenticationException {
        final SecurityContext context = SecurityContextHolder.getContext();
        if (context == null) {
            throw new AuthenticationException("Null context provided");
        }

        final Authentication authentication = context.getAuthentication();

        if (authentication == null) {
            throw new NoLoggedInUserException();
        }

        final Object principal = authentication.getPrincipal();

        if (principal instanceof UserDetails) {
            return ((UserDetails) principal).getUsername();
        }

        return principal.toString();
    }

    @Override
    public User getLoggedInUser() throws AuthenticationException {
        final String username = getCurrentUsername();

        final Optional<User> userFoundOptional = userRepository.findByUsername(username);
        return userFoundOptional.get();
    }
}
