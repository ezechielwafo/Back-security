package com.ezechiel.Config;

import com.ezechiel.Config.auth.UserDetailsServiceSecu;
import com.ezechiel.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
public class AppConfig {
    private final JwtAuthenticationFilter filtre;
    private final UserDetailsServiceSecu userDetailsServiceSecu;
    private final  UserRepository repository;
    // methode de creation du service permettant de charger les details de l'utilisateur
    @Bean
    public UserDetailsService userDetailsService(){ //creer une instance uitlisable pour charger les details d'utilisateurs
        return username -> repository.findByEmail(username)
                .orElseThrow(() ->new UsernameNotFoundException("User not found")); // Au cas ou /ou bien faire
    }
//    @Bean
//        public AuthenticationProvider authenticationProvider(){ //fourniseur d'authentification
//        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
//        authProvider.setUserDetailsService(userDetailsService());
//        authProvider.setPasswordEncoder(passwordEncoder());
//        return authProvider;
//    }
//    @Bean
//    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
//
//        return config.getAuthenticationManager();
//    }
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
            .csrf(csrf -> csrf.disable())
            .authorizeRequests()
            .requestMatchers( "/api/v1/auth/**")
            .permitAll()
            .anyRequest()
            .authenticated()
            .and()
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authenticationManager(authenticationManager(http))
            .addFilterBefore(filtre, UsernamePasswordAuthenticationFilter.class);
    return http.build();
}
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
@Bean
public AuthenticationManager authenticationManager(HttpSecurity httpSecurity) throws Exception {
    AuthenticationManagerBuilder authenticationManagerBuilder = httpSecurity.getSharedObject(AuthenticationManagerBuilder.class);
    authenticationManagerBuilder.userDetailsService(userDetailsServiceSecu).passwordEncoder(passwordEncoder());
    return   authenticationManagerBuilder.build();
}

}