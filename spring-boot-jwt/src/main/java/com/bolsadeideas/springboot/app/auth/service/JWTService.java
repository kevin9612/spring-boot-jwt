package com.bolsadeideas.springboot.app.auth.service;

import org.springframework.security.core.Authentication;

import io.jsonwebtoken.Claims;

public interface JWTService {

	String create(final Authentication authentication);
	
	Boolean validate(final String token);
	
	Claims getClaims(final String token);
	
	String getUsername(final String token);
	
	String resolve(final String token);
	
}
