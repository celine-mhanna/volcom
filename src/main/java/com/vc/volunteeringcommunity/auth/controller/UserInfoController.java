package com.vc.volunteeringcommunity.auth.controller;


import com.vc.volunteeringcommunity.auth.payload.response.UserInfoResponse;
import com.vc.volunteeringcommunity.auth.repository.UserRepository;
import com.vc.volunteeringcommunity.auth.security.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/me")
public class UserInfoController {
    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    UserRepository userRepository;

    @GetMapping("")
    public ResponseEntity<UserInfoResponse> getLoggedInUserInfo(@CookieValue(name = "Authorization") String jwt) {
        final String userName = jwtUtils.getUserNameFromJwtToken(jwt);
        final String displayName = userRepository.findByUsername(userName).get().getDisplayName();
        return ResponseEntity.ok().body(new UserInfoResponse(displayName));
    }
}
