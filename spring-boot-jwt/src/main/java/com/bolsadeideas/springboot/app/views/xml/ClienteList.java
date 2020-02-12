package com.bolsadeideas.springboot.app.views.xml;

import java.util.List;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.bolsadeideas.springboot.app.models.entity.Cliente;


/*
 * Etiqueta para definir que un objeto es de tipo xml, detro de la etiqueta
 * debe ri el nombre del objeto padre.
 */
@XmlRootElement(name = "clientes")
public class ClienteList {

	
	/*
	 * Etiqueta para el nombre de las variables.
	 */
	@XmlElement(name = "cliente")
	public List<Cliente> clientes;
	
	//El constructor vacio por defecto es obligatorio.
	public ClienteList() {
	}
	
	public ClienteList(final List<Cliente> clientes) {
		this.clientes = clientes;
	}
		
}
