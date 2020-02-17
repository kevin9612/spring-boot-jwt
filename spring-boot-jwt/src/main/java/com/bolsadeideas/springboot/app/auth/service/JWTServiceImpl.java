package com.bolsadeideas.springboot.app.auth.service;

import org.springframework.security.core.Authentication;

import io.jsonwebtoken.Claims;

public class JWTServiceImpl implements JWTService{

	@Override
	public String create(Authentication authentication) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Boolean validate(String token) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Claims getClaims(String token) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getUsername(String token) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String resolve(String token) {
		// TODO Auto-generated method stub
		return null;
	}

}
