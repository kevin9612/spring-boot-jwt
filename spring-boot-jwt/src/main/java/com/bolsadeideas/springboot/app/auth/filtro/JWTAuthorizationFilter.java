package com.bolsadeideas.springboot.app.auth.filtro;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.bolsadeideas.springboot.app.auth.SimpleGrantedAuthorityMixin;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	public JWTAuthorizationFilter(final AuthenticationManager authenticationManager) {
		super(authenticationManager);
		// TODO Auto-generated constructor stub
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		// En el header viene el token que se quiere validar, en la etiqueta
		// Authorization
		String header = request.getHeader("Authorization");

		if (!requeriesAuthentication(header)) {
			chain.doFilter(request, response);
			return;
		}

		Boolean validoToken;
		Claims token = null;
		// Con el metodo parser se puede validar el token, se pasa la llave secreta con
		// la que se codifica, se reemplazar el Bearer ya que este el la etiqueta del
		// metodo de autorizacion.
		try {
			token = Jwts.parser().setSigningKey("Alguna.clave.secreta.12345".getBytes())
					.parseClaimsJws(header.replace("Bearer ", "")).getBody();

			validoToken = true;
		} catch (Exception e) {
			validoToken = false;
		}

		UsernamePasswordAuthenticationToken authenticationToken = null;

		if (validoToken) {
			String username = token.getSubject();
			Object roles = token.get("authorities");
			Collection<? extends GrantedAuthority> authorities = Arrays.asList(
					new ObjectMapper().addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class)
							.readValue(roles.toString().getBytes(), SimpleGrantedAuthority[].class));
			authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
		}

		// Deontor d ela solicitud se inserta el token
		SecurityContextHolder.getContext().setAuthentication(authenticationToken);
		chain.doFilter(request, response);
	}

	protected boolean requeriesAuthentication(final String header) {
		if (header == null || !header.startsWith("Bearer ")) {
			return false;
		}
		return true;
	}

}
