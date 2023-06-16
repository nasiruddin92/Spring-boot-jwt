package com.security.naba.controller;


import com.security.naba.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class LoginController {

    @Autowired
    private AuthenticationService authenticationService;

    @PostMapping("/register")
    ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest registerRequest){
        return new ResponseEntity<>(authenticationService.register(registerRequest), HttpStatus.OK);
    }

    @PostMapping("/auth")
    ResponseEntity<AuthResponse> auth(@RequestBody AuthRequest authRequest){
        return new ResponseEntity<>(authenticationService.auth(authRequest), HttpStatus.OK);
    }

}
