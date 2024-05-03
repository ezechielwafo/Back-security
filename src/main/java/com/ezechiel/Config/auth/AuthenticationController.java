package com.ezechiel.Config.auth;

import lombok.RequiredArgsConstructor;
//import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
//import org.springframework.web.cors.CorsConfiguration;
//import org.springframework.web.cors.CorsConfigurationSource;
//import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

//@CrossOrigin(origins = "http://localhost:8090", maxAge = 3600, allowCredentials="true")

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@CrossOrigin("*")
public class AuthenticationController {
    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request
    ) {
        return ResponseEntity.ok(service.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request
    ) {
        return ResponseEntity.ok(service.authenticate(request));
    }

//    @PostMapping("/logout")
//    public ResponseEntity<Void> logout(
//            @RequestHeader("Authorization") String authorizationHeader
//    ) {
//        String token = authorizationHeader.replace("Bearer ", "");
//        service.invalidateToken(token);
//        return ResponseEntity.ok().build();
//    }
}