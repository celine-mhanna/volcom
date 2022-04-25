package com.vc.volunteeringcommunity.auth.security.services;


import com.vc.volunteeringcommunity.auth.model.User;
import com.vc.volunteeringcommunity.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.regex.Pattern;

@Service
public class UserAuthenticationServiceImpl implements UserAuthenticationService {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    private static final Logger log = LoggerFactory.getLogger(UserAuthenticationServiceImpl.class);

    @Override
    public void resetUserPassword(String username, String oldPassword, String newPassword) {
        final Optional<User> optionalUser = userRepository.findByUsername(username);
        final User user = optionalUser.get();
        if (!user.getActive()) {
            log.warn("Attempt to reset a deactivated user's password");
            throw new IllegalArgumentException("Username not found");
        } else if (!user.passwordNeedsReset()) {
            log.warn("Attempt to reset a user's password without it needing to be reset");
            throw new IllegalArgumentException("User's password does not need reset");
        }

        if (validatePasswordStrength(newPassword)) {
            try {
                authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, oldPassword));
            } catch (AuthenticationException ex) {
                throw new BadCredentialsException("Bad credentials");
            }
            final String encryptedNewPassword = new BCryptPasswordEncoder(12).encode(newPassword);

            final User newUser = User.UserBuilder.anUser()
                    .withId(user.getId())
                    .withUsername(username)
                    .withDisplayName(user.getDisplayName())
                    .withPassword(encryptedNewPassword)
                    .withRole(user.getRole())
                    .withIsActive(true)
                    .withPasswordNeedsReset(false)
                    .build();
            userRepository.save(newUser);

        }
    }

    private boolean validatePasswordStrength(String password) {
        final Pattern hasDigitRegex = Pattern.compile(".*\\d.*");
        final Pattern hasUpperCaseRegex = Pattern.compile(".*[A-Z].*");
        final Pattern hasLowerCaseRegex = Pattern.compile(".*[a-z].*");
        final Pattern hasSpecialCharacterRegex = Pattern.compile(".*[~`!@#$%^&*()_\\-+= {\\[}\\]|\\\\:;\"'<,>.?/].*");
        int passwordStrength = 0;
        if (hasDigitRegex.matcher(password).matches()) {
            log.info("hasDigit");
            passwordStrength++;
        }
        if (hasUpperCaseRegex.matcher(password).matches()) {
            log.info("hasUpper");

            passwordStrength++;
        }
        if (hasLowerCaseRegex.matcher(password).matches()) {
            log.info("hasLower");

            passwordStrength++;
        }
        if (hasSpecialCharacterRegex.matcher(password).matches()) {
            log.info("hasSpecialChar");
            passwordStrength++;
        }
        log.info("PASSWORD STRENGTH : " + passwordStrength);
        return passwordStrength >= 3;
    }


}
