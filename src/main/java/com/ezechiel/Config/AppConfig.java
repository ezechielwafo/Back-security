package com.ezechiel.Config;

import com.ezechiel.Config.auth.UserDetailsServiceSecu;
import com.ezechiel.user.UserRepository;
import com.zaxxer.hikari.pool.HikariProxyCallableStatement;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import com.nimbusds.jose.jwk.source.ImmutableSecret;

import javax.crypto.spec.SecretKeySpec;

@Configuration
@RequiredArgsConstructor
public class AppConfig {
//    private String secretkey="5dfbbaaa6863a366dec29109b41353c9593d61886c066f91b688f0d7be2559f6";
    private final JwtAuthenticationFilter filtre;
    private final UserDetailsServiceSecu userDetailsServiceSecu;
    private final  UserRepository repository;
//    @Autowired
//    JwtService jwtService;

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
//@Bean
//public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//    http
//            .csrf(csrf -> csrf.disable())
//            .cors(Customizer.withDefaults())
//            .authorizeRequests()
//            .requestMatchers( "/api/v1/auth/**")
//            .permitAll()
//            .anyRequest()
//            .authenticated()
//            .and()
//            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//            .authenticationManager(authenticationManager(http))
//            .oauth2ResourceServer(auth2->auth2.jwt(Customizer.withDefaults()))
//            .authenticationProvider(authenticationProvider())
//           .addFilterBefore(new JwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
//            .addFilterBefore(filtre, UsernamePasswordAuthenticationFilter.class);
//    return http.build();
//}
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults())
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
//    @Bean
//    public JwtDecoder jwtDecoder(){
//        SecretKeySpec secretKe= new SecretKeySpec(
//                this.secretkey.getBytes(), 0,this.secretkey.getBytes().length, "RSA");
//        return NimbusJwtDecoder.withSecretKey(secretKe).macAlgorithm(MacAlgorithm.HS512).build();
//    }
//    @Bean
//    public JwtEncoder jwtEncoder() {
//        return new NimbusJwtEncoder(new ImmutableSecret<>(this.secretkey.getBytes()));
//    }
//
////    @Bean
////    public DaoAuthenticationProvider authenticationProvider() {
////        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
////
////        authProvider.setUserDetailsService(userDetailsService());
////        authProvider.setPasswordEncoder(passwordEncoder());
////
////        return authProvider;
////    }
////
////
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
//    @Bean
//    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService){
//        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
//        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
//        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
//        return new ProviderManager(daoAuthenticationProvider);
//    }
    @Bean
    CorsConfigurationSource corsConfigurationSource(){
        CorsConfiguration corsConfiguration =new CorsConfiguration();
        corsConfiguration.addAllowedOrigin("*");
        corsConfiguration.addAllowedMethod("*");
        corsConfiguration.addAllowedHeader("*");
        //corsConfiguration.setExposedHeaders(List.of("x-auth-token"));
        UrlBasedCorsConfigurationSource source=new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**",corsConfiguration);
        return source;
    }

}