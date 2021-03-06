package com.bolsadeideas.springboot.app.auth.filtro;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.webresources.JarWarResourceSet;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.AntPathMatcher;

import com.bolsadeideas.springboot.app.models.entity.Usuario;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * 
 * Clase filtro la cual autentica de acuerdo a un usuario y conraseña, siempre
 * extiende de UsernamePasswordAuthenticationFilter.
 * 
 * @author kevin9612
 *
 */
public class JWTAutenticationFilter extends UsernamePasswordAuthenticationFilter {

	private AuthenticationManager authenticationManager;

	public JWTAutenticationFilter(final AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
		setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST"));
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {

		String username = obtainUsername(request);
		String password = obtainPassword(request);

//		if (username == null) {
//			username = "";
//		}
//
//		if (password == null) {
//			password = "";
//		}
		
		if (username != null && password != null) {
			logger.info("Usuario y clave en formulario");
			
			logger.info("usuario: "+username);
			logger.info("password: "+password);
		}else {
			//Convertir el json obtenido a un objeto de tipo usuario.
			Usuario user = null;
			try {
				user = new ObjectMapper().readValue(request.getInputStream(), Usuario.class);
				
				username = user.getUsername();
				password = user.getPassword();
				
				logger.info("usuario: "+username);
				logger.info("password: "+password);
				
			} catch (JsonParseException e) {
				e.printStackTrace();
			} catch (JsonMappingException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		username = username.trim();

		// Token interno, no es el mismo de JSONWebTken
		UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username,
				password);

		return authenticationManager.authenticate(authenticationToken);
	}

	/**
	 * Metodo para controlar que que no me he autenticado.
	 */
	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		Map<String, Object> body = new HashMap<>();
		
		//Objeto failed obtiene el error de porque no me he logrado autenticar
		body.put("mensaje", "Error de autenticación username o password incorrecto");
		body.put("error", failed.getMessage());
		
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		response.setStatus(401);
		response.setContentType("application/json");
	}

	/**
	 * Motodo para controlar que me he autenticado.
	 */
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {

		String username = ((User) authResult.getPrincipal()).getUsername();

		// Metodo el cual me retorna los roles
		Collection<? extends GrantedAuthority> roles = authResult.getAuthorities();

		Claims claims = Jwts.claims();
		claims.put("authorities", new ObjectMapper().writeValueAsString(roles));

		// A la hora de crear el token se pasa el usuario y y se cifra la clave.
		String token = Jwts.builder().setClaims(claims).setSubject(username)
				.signWith(SignatureAlgorithm.HS512, "Alguna.clave.secreta.12345".getBytes()).setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis() + 14000000L)).compact();
		super.successfulAuthentication(request, response, chain, authResult);

		// Bearer estandar en token.
		response.addHeader("Authorization", "Bearer " + token);

		Map<String, Object> body = new HashMap<String, Object>();
		body.put("token", token);
		body.put("user", (User) authResult.getPrincipal());
		body.put("mensaje", "Bienvenido usuario" + username + ", ingresaste con exito");

		// Seretorna el cuerpo del mensaje en un objeto JSON
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		response.setStatus(200);
		response.setContentType("application/json");
	}

}
