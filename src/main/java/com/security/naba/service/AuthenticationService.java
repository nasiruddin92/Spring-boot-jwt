package com.security.naba.service;

import com.security.naba.controller.AuthRequest;
import com.security.naba.controller.AuthResponse;
import com.security.naba.controller.RegisterRequest;

public interface AuthenticationService {
    AuthResponse register(RegisterRequest request);
    AuthResponse auth(AuthRequest request);
}
