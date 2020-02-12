package com.bolsadeideas.springboot.app.views;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.data.domain.Page;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.view.AbstractView;
import org.supercsv.io.CsvBeanWriter;
import org.supercsv.io.ICsvBeanWriter;
import org.supercsv.prefs.CsvPreference;

import com.bolsadeideas.springboot.app.models.entity.Cliente;

@Component("listar")
public class ClienteCsvView extends AbstractView{

	public ClienteCsvView() {
		setContentType("text/csv");
	}
	
	@Override
	protected void renderMergedOutputModel(final Map<String, Object> model, final HttpServletRequest request,
			final HttpServletResponse response) throws Exception {
		response.setHeader("Content-Disposition", "attachment; filename=\"clientes.csv\"");
		response.setContentType(getContentType());
		
		@SuppressWarnings("unchecked")
		Page<Cliente> clientes = (Page<Cliente>) model.get("clientes");
		ICsvBeanWriter beanWriter = new CsvBeanWriter(response.getWriter(), CsvPreference.STANDARD_PREFERENCE);
		
		//Se especifica el header de acuerdo a cada atributo que esta en el dto.
		String[] header = {"id", "nombre", "apellido", "email", "createAt"};
		//writeGeader es para escribir el header.
		beanWriter.writeHeader(header);
		
		for (Cliente cliente : clientes) {
			// write es ele metodo para escribir en el archivo.
			beanWriter.write(cliente, header);
		}
		beanWriter.close();
		
	}

	@Override
	protected boolean generatesDownloadContent() {
		return true;
	}

}
