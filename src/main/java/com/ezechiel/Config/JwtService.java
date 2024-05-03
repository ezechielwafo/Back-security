package com.ezechiel.Config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRET_KEY="ZVfpytppE9idXrF/5Fi85VZbXWnQ/nIxjz5Zan15SC4cBP2UqEr12E6/ruUib9dds79Pd2BxhI2QiBWz5LxErg==";
//    private String secretkey="5dfbbaaa6863a366dec29109b41353c9593d61886c066f91b688f0d7be2559f6";
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }
    //on Appel se type de methode Une methode generique qui prend en parametre de
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver)
    // ClaimsResolver c'est une fonction de resolution des revendications
    {
        final Claims claims= extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }
    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails){
        return Jwts
                .builder() //CREATION DU CONTRUCTEUR
                .setClaims(extraClaims)//definition de la revendication
                .setSubject(userDetails.getUsername())//definit le sujet du jeton name
                .setIssuedAt(new Date(System.currentTimeMillis())) // date emision
                .setExpiration(new Date(System.currentTimeMillis() + 1000 *60 *24)) //data expiration 24 apres creation
                .signWith(getSignInKey(), SignatureAlgorithm.HS512) //signe le jeton a partie de getS
                .compact(); //finalise en compacte en une chaine de caractere
    }
    //verification de la valid du token
    public boolean isTokenValid (String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }
    private boolean isTokenExpired(String token)
    {
        return extractExpiration(token).before(new Date());
    }
    private Date extractExpiration(String token){
        return extractClaim(token, Claims::getExpiration);
    }
    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder() //creation du constructeur qui permet de configurer les parametres de validation du token
                .setSigningKey(getSignInKey())//definition de la cle de signature
                .build()//methode utilise pour finaliser la configuration
                .parseClaimsJws(token)// verifie la validite
                .getBody();//recupere les elements validees
    }
    private Key getSignInKey() {
        byte[] keyBytes= Decoders.BASE64.decode(SECRET_KEY);// decoder la cle secret en hex
        return Keys.hmacShaKeyFor(keyBytes);//creer la clee  signature
    }

}