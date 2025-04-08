//package p2;

import java.util.Calendar;
import java.util.GregorianCalendar;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import java.util.Date;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;


/**
* Esta clase implementa el comportamiento de una CA
* @author Seg Red Ser
* @version 1.0
*/

/**
 * Si yo he generado un certificado de usuario y genero un nuevo par de claves y el CertificadoCA
 * (certificado de la CA firmado con la nueva clave Privada)
 * Cuando quiero validar ese certificado de Usuario con el Certificado de la CA, la firma no va a ser valida
 * Para verificar necesitamos la clave publica de la CA, obtenida en el certificado de la CA,
 * al generar un nuevo par de claves y un nuevo CertificadoCA, no se podra validar el certificado
 * del usuario que se firmo con una clave Privada antigua
 * SOLUCION: volver a generar el certificado del usuario con las nuevas claves
 * @author jucho
 *
 */
public class CA {
	
	private final X500Name nombreEmisor;
	private BigInteger numSerie;
	private final int añosValidez; 
	
	public final static String NOMBRE_FICHERO_CRT = "CertificadoCA.crt";
	public final static String NOMBRE_FICHERO_CLAVES = "CA-claves";
	
	private RSAKeyParameters clavePrivadaCA = null;
	private RSAKeyParameters clavePublicaCA = null;
	
	/**
	 * Constructor de la CA. 
	 * Inicializa atributos de la CA a valores por defecto
	 */
	public CA () {
		// Distinguished Name DN. C Country, O Organization name, CN Common Name. 
		this.nombreEmisor = new X500Name ("C=ES, O=DTE, CN=CA");
		this.numSerie = BigInteger.valueOf(1);
		this.añosValidez = 1; // Son los años de validez del certificado de usuario, para la CA el valor es 4
	}
	
	/**
	* Método que genera la parejas de claves y el certificado autofirmado de la CA.
	* @throws OperatorCreationException
	* @throws IOException 
	*/
	public void generarClavesyCertificado() throws OperatorCreationException, IOException {
		// Generar una pareja de claves (clase GestionClaves) y guardarlas EN FORMATO PEM en los ficheros 
                // indicados por NOMBRE_FICHERO_CLAVES (añadiendo al nombre las cadenas "_pri.txt" y "_pu.txt")
		
		
		// Se instancia un OBJETO de la clase GestionClaves
		GestionClaves gc = new GestionClaves (); 
		
		// Generar claves, me creo un atriburo AsymmmetricCipeherKeyPair y las almaceno ahi
		AsymmetricCipherKeyPair claves = gc.generarClaves(BigInteger.valueOf(17), 2048);
		
		// Asignar claves a los atributos correspondientes
		this.clavePrivadaCA = (RSAKeyParameters) claves.getPrivate();
		this.clavePublicaCA = (RSAKeyParameters) claves.getPublic();
		
		if (clavePublicaCA == null || clavePrivadaCA == null) {
            throw new RuntimeException("Error: No se ha generado ninguna clave.");
        }
		
		// ALMACENAR EN EL FORMATO PKCS8 para Privada y PKI para publica
		PrivateKeyInfo        clavePrivadaPKCS8 = gc.getClavePrivadaPKCS8(clavePrivadaCA);
		SubjectPublicKeyInfo  clavePublicaPKI   = gc.getClavePublicaSPKI(clavePublicaCA);
		
		if (clavePrivadaPKCS8 == null || clavePublicaPKI == null) {
            throw new RuntimeException("Error: No se ha cambiado de formato.");
        }
		
		// Escribir las claves en un fichero en formato PEM 
		GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.PKCS8KEY_PEM_HEADER, clavePrivadaPKCS8.getEncoded(), NOMBRE_FICHERO_CLAVES + "_pri.txt");
		GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.PUBLICKEY_PEM_HEADER, clavePublicaPKI.getEncoded(), NOMBRE_FICHERO_CLAVES + "_pu.txt");
		
		
		// Generar un certificado autofirmado: 
		// 	1. Configurar parámetros para el certificado e instanciar objeto X509v3CertificateBuilder
		// 	2. Configurar hash para resumen y algoritmo firma (MIRAR DIAPOSITIVAS DE APOYO EN MOODLE)
		//	3. Generar certificado
		//	4. Guardar el certificado en formato PEM como un fichero con extensión crt (NOMBRE_FICHERO_CRT)
		//COMPLETAR POR EL ESTUDIANTE
		
		
		// 1. Configurar parámetros para el certificado e instanciar objeto X509v3CertificateBuilder
		Date fechaHoy = new Date(System.currentTimeMillis());
		
		Calendar fin = GregorianCalendar.getInstance();
		fin.add(Calendar.YEAR, 4);                           //añadir 4 años al calendario Para la CA.
		Date fechaFin = fin.getTime();
		
		System.out.println("Fecha actual...:"+fechaHoy.toString()); // Momento actual
		System.out.println("fecha Fin Certificado :"+fechaFin.toString());
		
		X509v3CertificateBuilder certBldr= new X509v3CertificateBuilder(
				this.nombreEmisor,    // CA
				this.numSerie, 
				fechaHoy,
				fechaFin, 
				this.nombreEmisor,    // SUJETO
				clavePublicaPKI);     // FORMATO CLAVE PUBLICA SPKI
		
		
		// 2. Configurar hash para resumen y algoritmo firma
		DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new 
				DefaultSignatureAlgorithmIdentifierFinder(); // FIRMA
		DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new 
				DefaultDigestAlgorithmIdentifierFinder();    // RESUMEN
		
		AlgorithmIdentifier sigAlgId = sigAlgFinder.find("SHA256withRSA"); 
		AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId); 
		
		// 3. Generar certificado
		BcContentSignerBuilder csBuilder= new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
		
		// 4. Se genera y guarda en fichero (en formato PEM y con extensión .crt) el certificado autofirmad
		
		X509CertificateHolder holder = certBldr.build(csBuilder.build(this.clavePrivadaCA));
	
		// El certificado se firma con la clave Privada de CA
		// certBldr - builder del certificado
		// csBuilder -buider de la firma
		
		// GUARDAR EN EL FICHERO (formato PEM y extension .crt)
		GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.CERTIFICATE_PEM_HEADER, holder.getEncoded(), NOMBRE_FICHERO_CRT);
	}




	/**
	 * Método que carga la parejas de claves
	 * @throws IOException 
	 */
	public void cargarClaves () throws IOException{
        // Carga la pareja de claves de los ficheros indicados por NOMBRE_FICHERO_CLAVES 
        // (añadiendo al nombre las cadenas "_pri.txt" y "_pu.txt")
		
		// No carga el certificado porque se lee de fichero cuando se necesita.
		
		GestionClaves gc = new GestionClaves(); // Clase con métodos para manejar las claves
		
		try {
			// Carga la pareja de claves de los ficheros indicados por NOMBRE_FICHERO_CLAVES
	
			// Leemos los ficheros donde se encuentran las clave pública y privada.
			// Nos devuelve un objeto, al que le asignamos el tipo de formato correpondiente de la clave
			PrivateKeyInfo        clavePrivadaPKCS8 = (PrivateKeyInfo)       GestionObjetosPEM.leerObjetoPEM(NOMBRE_FICHERO_CLAVES + "_pri.txt");
			SubjectPublicKeyInfo  clavePublicaPKI   = (SubjectPublicKeyInfo) GestionObjetosPEM.leerObjetoPEM(NOMBRE_FICHERO_CLAVES + "_pu.txt");
	
			if (clavePrivadaPKCS8 == null || clavePublicaPKI == null) {
	            throw new RuntimeException("Error: No se ha cambiado de formato.");
	        }
			
			// Pasar a RSAKeyParameters
			this.clavePrivadaCA = gc.getClavePrivadaMotor(clavePrivadaPKCS8);
			this.clavePublicaCA = gc.getClavePublicaMotor(clavePublicaPKI);
			
			// Escribir las claves en un fichero en formato PEM de nuevo 
			GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.PKCS8KEY_PEM_HEADER, clavePrivadaPKCS8.getEncoded(), NOMBRE_FICHERO_CLAVES + "_pri.txt");
			GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.PUBLICKEY_PEM_HEADER, clavePublicaPKI.getEncoded(), NOMBRE_FICHERO_CLAVES + "_pu.txt");

		
		} catch (FileNotFoundException e) {
	        throw new FileNotFoundException("Error: Uno o ambos archivos de claves no existen: " + e.getMessage());
	    } catch (IOException e) {
	        throw new IOException("Error al leer los archivos de claves: " + e.getMessage());
	    }
	}


	
	/**
	 * Método que genera el certificado de un usuario a partir de una petición de certificación
	 * @param ficheroPeticion:String. Parámetro con la petición de certificación
	 * @param ficheroCertUsu:String. Parámetro con el nombre del fichero en el que se guardará el certificado del usuario
	 * @throws IOException 
	 * @throws PKCSException 
	 * @throws OperatorCreationException
	 */
	public boolean certificarPeticion(String ficheroPeticion, String ficheroCertUsu) throws IOException, 
	OperatorCreationException, PKCSException{
		
		boolean peticion = false;
		//  Verificar que están generadas las clave privada y pública de la CA
		if (clavePrivadaCA == null || clavePublicaCA == null) {
			System.out.println("Las claves no han sido generadas. TECLEE 1, para generar las claves de nuevo o TECLEE 2 para cargar las claves");
		}else {
		
		// Leer el fichero Peticion y obtener la informacion relevante (Nombre y la clave Publica del usuario)
		PKCS10CertificationRequest fichPeticion = (PKCS10CertificationRequest) GestionObjetosPEM.leerObjetoPEM(ficheroPeticion);
		
		X500Name sujeto = fichPeticion.getSubject();                // obtener el nombre usuario
		SubjectPublicKeyInfo clavePublicaUsr = fichPeticion.getSubjectPublicKeyInfo();   // obtener clave PUblica del usuario
		
		
		//  Verificar firma del solicitante (KPSolicitante en fichero de petición) 
		// Instanciar un objeto de la clase GestionClaves
		GestionClaves gc = new GestionClaves ();
		
		// 2. Obtener la clave PUBLICA en formato RSAKeyParameters
		RSAKeyParameters clavePublicaURSA = gc.getClavePublicaMotor(clavePublicaUsr);
		
		
		// 3. Generar un contenedor para la verificación
		DefaultDigestAlgorithmIdentifierFinder signer = new DefaultDigestAlgorithmIdentifierFinder();
		ContentVerifierProvider contentVerifierProvider = new BcRSAContentVerifierProviderBuilder(signer).build(clavePublicaURSA);
		
		// 4. VERIFICAR FIRMA
		if(!fichPeticion.isSignatureValid(contentVerifierProvider)) {
			peticion = false;
		}else
			peticion = true;
			
			//  Si la verificación es ok, se genera el certificado firmado con la clave privada de la CA
	        Date fechaHoy = new Date(System.currentTimeMillis());
			
			Calendar fin = GregorianCalendar.getInstance();
			fin.add(Calendar.YEAR, this.añosValidez);                           //añadir 1 años al calendario Para el certificado del Usuario.
			Date fechaFin = fin.getTime();
			
			System.out.println("Fecha actual...:"+fechaHoy.toString()); // Momento actual
			System.out.println("fecha Fin Certificado :"+fechaFin.toString());
			
			X509v3CertificateBuilder certBldr= new X509v3CertificateBuilder(
					this.nombreEmisor,    // CA
					this.numSerie, 
					fechaHoy,
					fechaFin, 
					sujeto,    // SUJETO
					clavePublicaUsr);     // FORMATO CLAVE PUBLICA SPKI
			
			KeyUsage usage = new KeyUsage(KeyUsage.digitalSignature);
			certBldr.addExtension(Extension.keyUsage, true, usage.getEncoded());
			
			// 2. Configurar hash para resumen y algoritmo firma
			DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new 
					DefaultSignatureAlgorithmIdentifierFinder(); // FIRMA
			DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new 
					DefaultDigestAlgorithmIdentifierFinder();    // RESUMEN
			
			AlgorithmIdentifier sigAlgId = sigAlgFinder.find("SHA256withRSA"); 
			AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId); 
			
			// 3. Generar certificado
			BcContentSignerBuilder csBuilder= new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
			
			// firmar el certificado y almacenar el certificado
			
			// 4. Se genera y guarda en fichero (en formato PEM y con extensión .crt) el certificado autofirmad
			X509CertificateHolder certUsuario = certBldr.build(csBuilder.build(this.clavePrivadaCA));
			
			// El certificado se firma con la clave Privada de CA
			// certBldr - builder del certificado
			// csBuilder -buider de la firma
			
			// GUARDAR EN EL FICHERO (formato PEM y extension .crt)
			GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.CERTIFICATE_PEM_HEADER, certUsuario.getEncoded(), ficheroCertUsu);	
		}
		return peticion;
	}
	
	public BcContentSignerBuilder confirmar_firma() {
		
		DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new 
				DefaultSignatureAlgorithmIdentifierFinder(); // FIRMA
		DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new 
				DefaultDigestAlgorithmIdentifierFinder();    // RESUMEN
		
		AlgorithmIdentifier sigAlgId = sigAlgFinder.find("SHA256withRSA"); 
		AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId); 
		
		BcContentSignerBuilder csb= new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
		
		return csb;
	}
	
}
	// EL ESTUDIANTE PODRÁ CODIFICAR TANTOS MÉTODOS PRIVADOS COMO CONSIDERE INTERESANTE PARA UNA MEJOR ORGANIZACIÓN DEL CÓDIGO