package com.vc.volunteeringcommunity.auth.security.jwt;

import java.util.Date;
import java.util.UUID;

import com.vc.volunteeringcommunity.auth.model.User;
import com.vc.volunteeringcommunity.auth.repository.UserRepository;
import com.vc.volunteeringcommunity.auth.security.PasswordNeedsResetException;
import com.vc.volunteeringcommunity.auth.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;


import io.jsonwebtoken.*;

@Component

public class JwtUtils {

    private final static String jwtSecret;

    @Autowired
    UserRepository userRepository;

    static {
        jwtSecret = UUID.randomUUID().toString();
    }

    @Value("${volcom.app.auth.session.timeout:3600}")
    private int jwtExpirationSeconds;

    public String generateJwtToken(Authentication authentication) throws PasswordNeedsResetException {

        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        final User user = userRepository.findByUsername(userPrincipal.getUsername()).get();

        if (!user.getActive()) {
            throw new BadCredentialsException("Bad credentials");
        } else if (user.passwordNeedsReset()) {
            throw new PasswordNeedsResetException("User password needs to be reset");
        }

        return Jwts.builder().setSubject((userPrincipal.getUsername())).setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + (jwtExpirationSeconds * 1000))).signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) throws SignatureException {
        Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
        return true;
    }

}
