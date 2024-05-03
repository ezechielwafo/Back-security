package com.ezechiel.Config.auth;

//import com.ezechiel.Config.JwtService;
import com.ezechiel.Config.JwtService;
import com.ezechiel.user.Role;
import com.ezechiel.user.User;
import com.ezechiel.user.UserRepository;
import lombok.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
//import org.springframework.security.oauth2.jwt.JwsHeader;
//import org.springframework.security.oauth2.jwt.JwtClaimsSet;
//import org.springframework.security.oauth2.jwt.JwtEncoder;
//import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
//import java.time.Instant;
//import java.time.temporal.ChronoUnit;
//import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class AuthenticationService{
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
//    @Autowired
//    JwtEncoder jwtEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
//    public AuthenticationResponse register(RegisterRequest request) {
//        JwtClaimsSet jwtClaimsSet= JwtClaimsSet.builder().build();
//        var user= User.builder()
//                .firstname(request.getFirstname())
//                .lastname(request.getLastname())
//                .email(request.getEmail())
//                .password(passwordEncoder.encode(request.getPassword()))
//                .role(Role.USER)
//                .build();
//        repository.save(user);
//        JwtEncoderParameters jwtEncoderParameters = JwtEncoderParameters.from(
//                JwsHeader.with(MacAlgorithm.HS512).build(),
//                jwtClaimsSet);
//        String jwtToken = jwtEncoder.encode(jwtEncoderParameters).getTokenValue();
//        return AuthenticationResponse.builder()
//                .token(jwtToken)
//                .build();
//    }
public AuthenticationResponse register(RegisterRequest request) {
    var user = User.builder()
            .firstname(request.getFirstname())
            .lastname(request.getLastname())
            .email(request.getEmail())
            .password(passwordEncoder.encode(request.getPassword()))
            .role(Role.USER)
            .build();
    repository.save(user);
    var jwtToken =jwtService.generateToken(user);
    return AuthenticationResponse.builder()
            .token(jwtToken)
            .build();
}
//    public AuthenticationResponse authenticate(AuthenticationRequest request) {
//        Authentication authentication= authenticationManager.authenticate(
//                new UsernamePasswordAuthenticationToken(
//                        request.getEmail(),
//                        request.getPassword()
//                )
//        );
//        Instant instant=Instant.now();
//        String scope = authentication.getAuthorities() .stream().toString();
//        JwtClaimsSet jwtClaimsSet=JwtClaimsSet.builder()
//                .issuedAt(instant)
//                .expiresAt(instant.plus(10, ChronoUnit.MINUTES))
//                .subject(String.valueOf(request))
//                .claim("scope", scope)
//                .build();
//        JwtEncoderParameters jwtEncoderParameters = JwtEncoderParameters.from(
//                JwsHeader.with(MacAlgorithm.HS512).build(),
//                jwtClaimsSet
//        );
//        String jwtToken = jwtEncoder.encode(jwtEncoderParameters).getTokenValue();
////        System.out.printf("\n\n\n return "+ jwt);
//        return AuthenticationResponse.builder().token(jwtToken).build();
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
         authenticationManager.authenticate(
                 new UsernamePasswordAuthenticationToken(
                         request.getEmail(),
                         request.getPassword()
                 )
         );

         var user = repository.findByEmail(request.getEmail())
                 .orElseThrow();
         var jwtToken =jwtService.generateToken(user);

        return AuthenticationResponse.builder().token(jwtToken).build();
    }

}
//    public AuthenticationService(JwtTokenProvider jwtTokenProvider, RedisTemplate<String, Object> redisTemplate) {
//        this.jwtTokenProvider = jwtTokenProvider;
//        this.redisTemplate = redisTemplate;
//    }
//
//    public void invalidateToken(String token) {
//        String username = jwtTokenProvider.getUsernameFromToken(token);
//        redisTemplate.opsForValue().set("blacklist:" + username, token, jwtTokenProvider.getTokenValidityInSeconds(), TimeUnit.SECONDS);
//    }
//    public void invalidateToken(String token) {
//
//    }
