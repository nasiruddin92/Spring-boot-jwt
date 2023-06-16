package com.security.naba.service.impl;


import com.security.naba.config.JwtService;
import com.security.naba.controller.AuthRequest;
import com.security.naba.controller.AuthResponse;
import com.security.naba.controller.RegisterRequest;
import com.security.naba.entity.Role;
import com.security.naba.entity.User;
import com.security.naba.repository.UserRepository;
import com.security.naba.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import lombok.var;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    @Autowired
    private  UserRepository userRepository;

    @Autowired
    private  PasswordEncoder passwordEncoder;
    @Autowired
    private  JwtService jwtService;
    @Autowired
    private  AuthenticationManager authenticationManager;

    @Override
    public AuthResponse register(RegisterRequest request){
        User user= User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user);
        String jwtToken=jwtService.generateToken(user);

        return AuthResponse.builder().token(jwtToken).build();

    }

    @Override
    public AuthResponse auth(AuthRequest request){
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(),request.getPassword()));
        User user=userRepository.findByEmail(request.getEmail()).orElseThrow(()-> new UsernameNotFoundException("User Not found !!"));
        String jwtToken=jwtService.generateToken(user);

        return AuthResponse.builder().token(jwtToken).build();
    }
}
