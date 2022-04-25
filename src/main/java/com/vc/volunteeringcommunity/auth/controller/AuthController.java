package com.vc.volunteeringcommunity.auth.controller;

import com.vc.volunteeringcommunity.auth.model.User;
import com.vc.volunteeringcommunity.auth.payload.request.LoginRequest;
import com.vc.volunteeringcommunity.auth.payload.request.RegisterRequest;
import com.vc.volunteeringcommunity.auth.repository.UserRepository;
import com.vc.volunteeringcommunity.auth.security.PasswordNeedsResetException;
import com.vc.volunteeringcommunity.auth.security.jwt.JwtUtils;
import com.vc.volunteeringcommunity.auth.security.services.LoginHistoryService;
import com.vc.volunteeringcommunity.auth.security.services.UserAuthenticationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.Optional;


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    LoginHistoryService loginHistoryService;

    @Autowired
    UserAuthenticationService userAuthenticationService;

    @Autowired
    UserRepository userRepository;

    @Autowired
    JwtUtils jwtUtils;

    @Value("${volcom.app.auth.session.timeout:3600}")
    private int sessionExpirationSeconds;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest, HttpServletResponse res, HttpServletRequest req) throws PasswordNeedsResetException {

        if (isAuthenticated()) {
            return ResponseEntity.ok().body("Already authenticated");
        }
        final String username = loginRequest.getUsername();


        log.info("Logging in user");
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt;
        jwt = jwtUtils.generateJwtToken(authentication);

        try {
            loginHistoryService.addLoginRecord(jwtUtils.getUserNameFromJwtToken(jwt), req);
        } catch (UsernameNotFoundException ex) {
            log.error("Non existent user successfully logged in", ex);
        }

        final String COOKIE_ATTRIBUTES = "HttpOnly; Path=/; SameSite=Lax; Max-Age=" + sessionExpirationSeconds;
        res.addHeader(HttpHeaders.SET_COOKIE, "Authorization=" + jwt + ";" + COOKIE_ATTRIBUTES);
        return ResponseEntity.ok().build();


    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody LoginRequest registerRequest, HttpServletResponse res, HttpServletRequest req) throws PasswordNeedsResetException {
        final String username = registerRequest.getUsername();
        final String password = registerRequest.getPassword();


        log.info("Registering user {} with password {}", username, password);

        try {
            final User user = User.UserBuilder.anUser()
                    .withUsername(username)
                    .withDisplayName(username)
                    .withRole("ROLE_USER")
                    .withPasswordNeedsReset(false)
                    .withIsActive(true)
                    .withPassword(getEncodedPassword(password))
                    .build();
            userRepository.save(user);
            System.out.println("User created");
        } catch (Exception ex) {
            log.error("Error creating user", ex);
            return ResponseEntity
                    .internalServerError()
                    .build();
        }

        return ResponseEntity
                .ok()
                .build();
    }

    private String getEncodedPassword(String password) {
        return new BCryptPasswordEncoder(12).encode(password);
    }

    private boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || AnonymousAuthenticationToken.class.
                isAssignableFrom(authentication.getClass())) {
            return false;
        }
        return authentication.isAuthenticated();
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(HttpServletResponse res) {
        log.info("User logout");
        final String DELETE_COOKIE_ATTRIBUTES = "Authorization=null; Max-Age=-1; HttpOnly; Path=/; SameSite=Lax";
        res.addHeader(HttpHeaders.SET_COOKIE, DELETE_COOKIE_ATTRIBUTES);
        return ResponseEntity.ok().build();
    }

}
