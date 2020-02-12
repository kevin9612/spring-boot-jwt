package com.bolsadeideas.springboot.app.views.xml;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.oxm.Marshaller;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.view.xml.MarshallingView;

import com.bolsadeideas.springboot.app.models.entity.Cliente;

/**
 * 
 * @author kevin9612
 *	Clase View de cliente la cual extiende de la vista MarshallingView.
 */
@Component("listar.xml")
public class ClienteListXmlView extends MarshallingView{


	@Autowired
	public ClienteListXmlView(Marshaller marshaller) {
		super(marshaller);
	}

	@SuppressWarnings("unused")
	@Override
	protected void renderMergedOutputModel(Map<String, Object> model, HttpServletRequest request,
			HttpServletResponse response) throws Exception {		
		
		model.remove("tituListlo");
		model.remove("page");
		Page<Cliente> clientes = (Page<Cliente>) model.get("clientes");
		
		model.remove("cliente");
		
		model.put("clienteList", new ClienteList(clientes.getContent()));
		super.renderMergedOutputModel(model, request, response);
	}

}
