package com.bolsadeideas.springboot.app.views.pdf;

import java.awt.Color;
import java.util.Locale;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.view.document.AbstractPdfView;

import com.bolsadeideas.springboot.app.models.entity.Factura;
import com.bolsadeideas.springboot.app.models.entity.ItemFactura;
import com.lowagie.text.Document;
import com.lowagie.text.Phrase;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfTable;
import com.lowagie.text.pdf.PdfWriter;

/**
 * Clase la cual exporta mi pdf.
 * 
 * @Component me permite acceder a la clase con la url definida. bean. Cualquier
 *            clase que estiende de abstractView o implemente view podra ser
 *            renderizada.
 * 
 * @author kevin9612
 *
 */

@Component("factura/ver")
public class FacturaPdfView extends AbstractPdfView {
	
	@Autowired
    private MessageSource messageSource;
	
	@Autowired
    private LocaleResolver localeResolver;

	@Override
	protected void buildPdfDocument(Map<String, Object> model, Document document, PdfWriter writer,
			HttpServletRequest request, HttpServletResponse response) throws Exception {

		Factura factura = (Factura) model.get("factura");
		
		Locale locale = localeResolver.resolveLocale(request);
		messageSource.getMessage("text.login.success", null, locale);

		// Metodo el cual se encarga de realizar la traduccion, propiedad de la clase AbstractPdfView 
		MessageSourceAccessor mensajes = getMessageSourceAccessor();
		// Table de pdf
		PdfPTable tabla = new PdfPTable(1);
		tabla.setSpacingAfter(20);
		
		PdfPCell cell = new PdfPCell(new Phrase(messageSource.getMessage("text.factura.ver.datos.cliente", null, locale)));
		//Insertar color en la celda.
		cell.setBackgroundColor(new Color(185, 230, 255));
		cell.setPadding(8f);
		tabla.addCell(cell);
		tabla.addCell(factura.getCliente().getNombre() + " " + factura.getCliente().getApellido());

		// Table de pdf
		PdfPTable tabla2 = new PdfPTable(1);
		tabla2.setSpacingAfter(20);
		
		cell = new PdfPCell(new Phrase(messageSource.getMessage("text.factura.ver.datos.cliente", null, locale)));
		cell.setBackgroundColor(new Color(184, 218, 255));
		cell.setPadding(8f);
		
		tabla2.addCell(cell);
		tabla2.addCell(mensajes.getMessage("text.cliente.factura.folio")+factura.getId());
		tabla2.addCell(mensajes.getMessage("text.cliente.factura.descripcion")+factura.getDescripcion());
		tabla2.addCell(mensajes.getMessage("text.cliente.factura.fecha")+factura.getCreateAt());
		//document es el objeto el cual me permite armar mi archivo.
		document.add(tabla);
		document.add(tabla2);
		
		PdfPTable table3 = new PdfPTable(4);
		table3.setWidths(new float[] {2.5f, 1f, 1f, 1f});
		table3.addCell(mensajes.getMessage("text.factura.form.item.nombre"));
		table3.addCell(mensajes.getMessage("text.factura.form.item.precio"));
		table3.addCell(mensajes.getMessage("text.factura.form.item.cantidad"));
		table3.addCell(mensajes.getMessage("text.factura.form.item.total"));
		
		for (ItemFactura item : factura.getItems()) {
			table3.addCell(item.getProducto().getNombre());
			table3.addCell(item.getProducto().getPrecio().toString());
			table3.addCell(item.getCantidad().toString());
			table3.addCell(item.calcularImporte().toString());
		}
		
		//Celda en pdf
		cell = new PdfPCell(new Phrase("text.cliente.factura.total"));
		cell.setColspan(3);
		cell.setHorizontalAlignment(PdfPCell.ALIGN_RIGHT);
		table3.addCell(cell);
		table3.addCell(factura.getTotal().toString());
		
		document.add(table3);
	}

}
