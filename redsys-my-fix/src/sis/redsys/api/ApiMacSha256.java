package sis.redsys.api;

import org.json.JSONObject;

import static sis.redsys.api.ApiWsMacSha256.*;

public class ApiMacSha256 {


	/** Array de DatosEntrada */
	private JSONObject jsonObj = new JSONObject();

	/** Set parameter */
	public  void setParameter(final String key, final String value) {
		jsonObj.put(key, value);
	}

	/** Get parameter */
	public  String getParameter(final String key) {
		return jsonObj.getString(key);
	}


	//////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////
	//////////// 		FUNCIONES PARA LA GENERACIÓN DEL FORMULARIO DE PAGO: 				 ////////////
	//////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////
	public  String getOrder() {
		if (getParameter("DS_MERCHANT_ORDER") == null || getParameter("DS_MERCHANT_ORDER").equals("")) {
			return getParameter("Ds_Merchant_Order");
		} else {
			return getParameter("DS_MERCHANT_ORDER");
		}
	}

	public  String createMerchantParameters() throws Exception {
		String jsonString = jsonObj.toString();
		String res = encodeB64String(jsonString.getBytes("UTF-8"));
		return res;
	}

	public  String createMerchantSignature(final String claveComercio) throws Exception {
		String merchantParams = createMerchantParameters();

		byte [] clave = decodeB64(claveComercio.getBytes("UTF-8"));
		String secretKc = toHexadecimal(clave, clave.length);
		byte [] secretKo = encrypt_3DES(secretKc, getOrder());

		// Se hace el MAC con la clave de la operación "Ko" y se codifica en BASE64
		byte [] hash = mac256(merchantParams, secretKo);
		String res = encodeB64String(hash);
		return res;
	}

	//////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////
	//////////// FUNCIONES PARA LA RECEPCIÓN DE DATOS DE PAGO (Notif, URLOK y URLKO): ////////////
	//////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////

	public  String getOrderNotif() {
		if (getParameter("Ds_Order") == null || getParameter("Ds_Order").equals("")) {
			return getParameter("DS_ORDER");
		} else {
			return getParameter("Ds_Order");
		}
	}

	public static String getOrderNotifSOAP(final String datos) {
		int posPedidoIni = datos.indexOf("<Ds_Order>");
		int tamPedidoIni = "<Ds_Order>".length();
		int posPedidoFin = datos.indexOf("</Ds_Order>");
		return datos.substring(posPedidoIni + tamPedidoIni, posPedidoFin);
	}

	public static String getRequestNotifSOAP(final String datos) {
		int posReqIni = datos.indexOf("<Request");
		int posReqFin = datos.indexOf("</Request>");
		int tamReqFin = "</Request>".length();
		return datos.substring(posReqIni, posReqFin + tamReqFin);
	}

	public static String getResponseNotifSOAP(final String datos) {
		int posResIni = datos.indexOf("<Response");
		int posResFin = datos.indexOf("</Response>");
		int tamResFin = "</Response>".length();
		return datos.substring(posResIni, posResFin + tamResFin);
	}

	public  String decodeMerchantParameters(final String datos) throws Exception {
		byte [] res = decodeB64UrlSafe(datos.getBytes("UTF-8"));
		String params = new String(res, "UTF-8");
		jsonObj = new JSONObject(params);
		return new String(res, "UTF-8");
	}

	public  String createMerchantSignatureNotif(final String claveComercio, final String merchantParams)
			throws Exception {
		byte [] clave = decodeB64(claveComercio.getBytes("UTF-8"));
		String secretKc = toHexadecimal(clave, clave.length);
		byte [] secretKo = encrypt_3DES(secretKc, getOrderNotif());

		// Se hace el MAC con la clave de la operación "Ko" y se codifica en BASE64
		byte [] hash = mac256(merchantParams, secretKo);
		byte [] res = encodeB64UrlSafe(hash);
		return new String(res, "UTF-8");
	}

	/******  Notificaciones SOAP ENTRADA ******/
	public  String createMerchantSignatureNotifSOAPRequest(final String claveComercio, final String request)
	throws Exception {
		byte [] clave = decodeB64(claveComercio.getBytes("UTF-8"));
		String secretKc = toHexadecimal(clave, clave.length);
		byte [] secretKo = encrypt_3DES(secretKc, getOrderNotifSOAP(request));
		
		// Se hace el MAC con la clave de la operación "Ko" y se codifica en BASE64
		byte [] hash = mac256(getRequestNotifSOAP(request), secretKo);
		byte [] res = encodeB64UrlSafe(hash);
		return new String(res, "UTF-8");
	}

	/******  Notificaciones SOAP SALIDA ******/
	public  String createMerchantSignatureNotifSOAPResponse(final String claveComercio, final String response, final String numPedido)
	throws Exception {
		byte [] clave = decodeB64(claveComercio.getBytes("UTF-8"));
		String secretKc = toHexadecimal(clave, clave.length);
		byte [] secretKo = encrypt_3DES(secretKc, numPedido);
		
		// Se hace el MAC con la clave de la operación "Ko" y se codifica en BASE64
		byte [] hash = mac256(getResponseNotifSOAP(response), secretKo);
		byte [] res = encodeB64UrlSafe(hash);
		return new String(res, "UTF-8");
	}	
}