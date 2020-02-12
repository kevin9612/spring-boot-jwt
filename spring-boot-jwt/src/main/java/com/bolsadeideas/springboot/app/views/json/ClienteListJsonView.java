package com.bolsadeideas.springboot.app.views.json;

import java.util.Map;

import org.springframework.data.domain.Page;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;

import com.bolsadeideas.springboot.app.models.entity.Cliente;
import com.bolsadeideas.springboot.app.views.xml.ClienteList;

@Component("listar.json")
public class ClienteListJsonView extends MappingJackson2JsonView {

	@SuppressWarnings("unchecked")
	@Override
	protected Object filterModel(Map<String, Object> model) {

		model.remove("tituListlo");
		model.remove("page");

		Page<Cliente> clientes = (Page<Cliente>) model.get("clientes");

		model.remove("cliente");
		model.put("clienteList", new ClienteList(clientes.getContent()));

		return super.filterModel(model);
	}

}
