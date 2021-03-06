package com.bolsadeideas.springboot.app.views.xlsx;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.math3.analysis.function.Ceil;
import org.apache.poi.ss.usermodel.BorderStyle;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellStyle;
import org.apache.poi.ss.usermodel.FillPatternType;
import org.apache.poi.ss.usermodel.IndexedColors;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.view.document.AbstractXlsxView;

import com.bolsadeideas.springboot.app.models.entity.Factura;
import com.bolsadeideas.springboot.app.models.entity.ItemFactura;

@Component("factura/ver.xlsx")
public class FacturaXlsxView extends AbstractXlsxView{

	@Override
	protected void buildExcelDocument(final Map<String, Object> model, final Workbook workbook, final HttpServletRequest request,
			final HttpServletResponse response) throws Exception {
		
		//Response el cual expcifica el nombre del archivo
		response.setHeader("Content-Disposition", "attachment; filename=\"facturas_view\"");
		
		//Se obtiene la factura del model
		final Factura factura = (Factura) model.get("factura");
		
		//Columna del excel
		Sheet sheet = workbook.createSheet();
		
		//Fila del excel
		Row row = sheet.createRow(0);
		Cell cell = row.createCell(0);
		
		cell.setCellValue("Datos del cliente");
		row = sheet.createRow(1);
		cell.setCellValue(factura.getCliente().getNombre() + " "+ factura.getCliente().getApellido());
		
		row = sheet.createRow(2);
		cell = row.createCell(0);
		cell.setCellValue(factura.getCliente().getEmail());
		
		sheet.createRow(4).createCell(0).setCellValue("Datos de la factura");
		sheet.createRow(5).createCell(0).setCellValue("Folio: "+factura.getId());
		sheet.createRow(6).createCell(0).setCellValue("Descripcion: "+factura.getDescripcion());
		sheet.createRow(7).createCell(0).setCellValue("Fecha: "+factura.getCreateAt());
		
		//Estilos de las celdas
		CellStyle theaderStyle = workbook.createCellStyle();
		theaderStyle.setBorderBottom(BorderStyle.MEDIUM);
		theaderStyle.setBorderTop(BorderStyle.MEDIUM);
		theaderStyle.setBorderRight(BorderStyle.MEDIUM);
		theaderStyle.setBorderLeft(BorderStyle.MEDIUM);
		theaderStyle.setFillForegroundColor(IndexedColors.GOLD.index);
		theaderStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);
		
		CellStyle tbodyStyle = workbook.createCellStyle();
		tbodyStyle.setBorderBottom(BorderStyle.MEDIUM);
		tbodyStyle.setBorderTop(BorderStyle.MEDIUM);
		tbodyStyle.setBorderRight(BorderStyle.MEDIUM);
		tbodyStyle.setBorderLeft(BorderStyle.MEDIUM);
		
		Row header = sheet.createRow(9);
		header.createCell(0).setCellValue("Producto");
		header.createCell(1).setCellValue("Precio");
		header.createCell(2).setCellValue("Cantidad");
		header.createCell(3).setCellValue("Total");
		
		header.getCell(0).setCellStyle(theaderStyle);
		header.getCell(1).setCellStyle(theaderStyle);
		header.getCell(2).setCellStyle(theaderStyle);
		header.getCell(3).setCellStyle(theaderStyle);
		
		int rownum = 10;
		for (ItemFactura item : factura.getItems()) {
			Row fila = sheet.createRow(rownum++);
			
			cell = fila.createCell(0);
			cell.setCellValue(item.getProducto().getNombre());
			cell.setCellStyle(tbodyStyle);
			
			cell = fila.createCell(1);
			cell.setCellValue(item.getProducto().getNombre());
			cell.setCellStyle(tbodyStyle);
			
			cell = fila.createCell(2);
			cell.setCellValue(item.getProducto().getPrecio());
			cell.setCellStyle(tbodyStyle);
			
			cell = fila.createCell(3);
			cell.setCellValue(item.getCantidad());
			cell.setCellStyle(tbodyStyle);
			
			cell = fila.createCell(4);
			cell.setCellValue(item.calcularImporte());
			cell.setCellStyle(tbodyStyle);
		}
		
		Row filaTotal = sheet.createRow(rownum);
		filaTotal.createCell(2).setCellValue("Gran total: ");
		filaTotal.createCell(2).setCellValue(factura.getTotal());
	}

	
}
