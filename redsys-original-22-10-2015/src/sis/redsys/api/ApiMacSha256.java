package sis.redsys.api;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.util.Arrays;
import org.json.JSONObject;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;


public class ApiMacSha256 {

	/** Numero de bytes para obtener cadenas multiplos de 8 */
	private static final short OCHO = 8;

	/** Constante de array de inicialización */
	private static final byte [] IV = {0, 0, 0, 0, 0, 0, 0, 0};

	/** Array de DatosEntrada */
	private static JSONObject jsonObj = new JSONObject();

	/** Set parameter */
	public static void setParameter(final String key, final String value) {
		jsonObj.put(key, value);
	}

	/** Get parameter */
	public static String getParameter(final String key) {
		return jsonObj.getString(key);
	}

	//////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////
	//////////// 					FUNCIONES AUXILIARES: 											  ///////////
	//////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////

	/** 3DES Function */
	public static byte [] encrypt_3DES(final String claveHex, final String datos) {
		byte [] ciphertext = null;
		try {
			// Crea la clave
			DESedeKeySpec desKeySpec = new DESedeKeySpec(toByteArray(claveHex));
			SecretKey desKey = new SecretKeySpec(desKeySpec.getKey(), "DESede");
			// Crea un cifrador
			Cipher desCipher = Cipher.getInstance("DESede/CBC/NoPadding");

			// Inicializa el cifrador para encriptar
			desCipher.init(Cipher.ENCRYPT_MODE, desKey, new IvParameterSpec(IV));

			// Se añaden los 0 en bytes necesarios para que sea un múltiplo de 8
			int numeroCerosNecesarios = OCHO - (datos.length() % OCHO);
			if (numeroCerosNecesarios == OCHO) {
				numeroCerosNecesarios = 0;
			}
			ByteArrayOutputStream array = new ByteArrayOutputStream();
			array.write(datos.getBytes("UTF-8"), 0, datos.length());
			for (int i = 0; i < numeroCerosNecesarios; i++) {
				array.write(0);
			}
			byte [] cleartext = array.toByteArray();
			// Encripta el texto
			ciphertext = desCipher.doFinal(cleartext);
		} catch (Exception e) {
			e.printStackTrace(System.err);
		}
		return ciphertext;
	}

	/** Base64 y HEX Functions */
	public static String encodeB64String(final byte [] data) throws Exception {
		return new String(Base64.encodeBase64(data), "UTF-8");
	}

	public static byte [] encodeB64(final byte [] data) throws Exception {
		return Base64.encodeBase64(data);
	}

	public static byte [] encodeB64UrlSafe(final byte [] data) {
		byte [] encode = Base64.encodeBase64(data);
		for (int i = 0; i < encode.length; i++) {
			if (encode[i] == '+') {
				encode[i] = '-';
			} else if (encode[i] == '/') {
				encode[i] = '_';
			}
		}
		return encode;
	}

	public static String decodeB64String(final byte [] data) throws Exception {
		return new String(Base64.decodeBase64(data), "UTF-8");
	}

	public static byte [] decodeB64(final byte [] data) throws Exception {
		return Base64.decodeBase64(data);
	}

	public static byte [] decodeB64UrlSafe(final byte [] data) {
		byte [] encode = Arrays.copyOf(data, data.length);
		for (int i = 0; i < encode.length; i++) {
			if (encode[i] == '-') {
				encode[i] = '+';
			} else if (encode[i] == '_') {
				encode[i] = '/';
			}
		}
		return Base64.decodeBase64(encode);
	}

	public static String toHexadecimal(byte [] datos, int numBytes) {
		String resultado = "";
		ByteArrayInputStream input = new ByteArrayInputStream(datos, 0, numBytes);
		String cadAux;
		int leido = input.read();
		while (leido != -1) {
			cadAux = Integer.toHexString(leido);
			if (cadAux.length() < 2)// Hay que añadir un 0
				resultado += "0";
			resultado += cadAux;
			leido = input.read();
		}
		return resultado;
	}

	public static byte[] toByteArray(String cadena){
		//Si es impar se añade un 0 delante
		if(cadena.length() % 2 != 0)
			cadena = "0"+cadena;
			
		int longitud = cadena.length()/2;
		int posicion = 0;
		String cadenaAux =null;
		ByteArrayOutputStream salida = new ByteArrayOutputStream();
		for(int i=0 ;i < longitud ;i++)
		{
			cadenaAux = cadena.substring(posicion,posicion+2);
			posicion +=2;
			salida.write((char)Integer.parseInt(cadenaAux,16));
		}
		return salida.toByteArray();
	}

	/** MAC Function */
	public static byte [] mac256(final String dsMerchantParameters, final byte [] secretKo) throws Exception {
		// Se hace el MAC con la clave de la operación "Ko" y se codifica en BASE64
		Mac sha256HMAC = Mac.getInstance("HmacSHA256");
		SecretKeySpec secretKey = new SecretKeySpec(secretKo, "HmacSHA256");
		sha256HMAC.init(secretKey);
		byte [] hash = sha256HMAC.doFinal(dsMerchantParameters.getBytes("UTF-8"));
		return hash;
	}

	//////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////
	//////////// 		FUNCIONES PARA LA GENERACIÓN DEL FORMULARIO DE PAGO: 				 ////////////
	//////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////
	public static String getOrder() {
		if (getParameter("DS_MERCHANT_ORDER") == null || getParameter("DS_MERCHANT_ORDER").equals("")) {
			return getParameter("Ds_Merchant_Order");
		} else {
			return getParameter("DS_MERCHANT_ORDER");
		}
	}

	public static String createMerchantParameters() throws Exception {
		String jsonString = jsonObj.toString();
		String res = encodeB64String(jsonString.getBytes("UTF-8"));
		return res;
	}

	public static String createMerchantSignature(final String claveComercio) throws Exception {
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

	public static String getOrderNotif() {
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

	public static String decodeMerchantParameters(final String datos) throws Exception {
		byte [] res = decodeB64UrlSafe(datos.getBytes("UTF-8"));
		String params = new String(res, "UTF-8");
		jsonObj = new JSONObject(params);
		return new String(res, "UTF-8");
	}

	public static String createMerchantSignatureNotif(final String claveComercio, final String merchantParams)
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
	public static String createMerchantSignatureNotifSOAPRequest(final String claveComercio, final String request)
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
	public static String createMerchantSignatureNotifSOAPResponse(final String claveComercio, final String response, final String numPedido)
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