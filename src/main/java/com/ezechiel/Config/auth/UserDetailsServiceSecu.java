package com.ezechiel.Config.auth;
import com.ezechiel.user.User;
import com.ezechiel.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceSecu implements UserDetailsService {
    private final UserRepository repo;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
      User  user = repo.findByEmail(username).orElseThrow();
        return user;
    }
}
