package com.bolsadeideas.springboot.app.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.bolsadeideas.springboot.app.models.service.IClienteService;
import com.bolsadeideas.springboot.app.views.xml.ClienteList;


/**
 * Anotacion que combina las anotaciones Controller y responseBody, propiedades de los servivios rest 
 * La etiqueta ResuestMapping es una anotacion la cual permite generar un prefijo de url local.
 *
 */
@RestController
@RequestMapping("/api/clientes")
public class ClienteRestController {

	@Autowired
	private IClienteService clienteService;
	
	@GetMapping(value = "/api/listar-rest")
	public ClienteList listar() {
		return new ClienteList(clienteService.findAll());
	}	
}
