//package p2;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.operator.OperatorCreationException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS10CertificationRequestBuilder;


/**
* Esta clase implementa el comportamiento de un usuario en una Infraestructura de Certificación
* @author Seg Red Ser
* @version 1.0
*/
public class Usuario {
	
	private RSAKeyParameters clavePrivada = null;
	private RSAKeyParameters clavePublica = null;


	/**
	 * Método que genera las claves del usuario.
	 * @param fichClavePrivada: String con el nombre del fichero donde se guardará la clave privada en formato PEM
	 * @param fichClavePublica: String con el nombre del fichero donde se guardará la clave publica en formato PEM
     * @throws IOException 	
	
	 */
	public void generarClavesUsuario (String fichClavePrivada, String fichClavePublica) throws IOException{
		
		// Se instancia un OBJETO de la clase GestionClaves
		GestionClaves gc = new GestionClaves (); 
		
		// Generar claves, me creo un atriburo AsymmmetricCipeherKeyPair y las almaceno ahi
		AsymmetricCipherKeyPair claves = gc.generarClaves(BigInteger.valueOf(17), 2048);
		
		// Asignar claves a los atributos correspondientes
		this.clavePrivada = (RSAKeyParameters) claves.getPrivate();
		this.clavePublica = (RSAKeyParameters) claves.getPublic();
		
		if (clavePublica == null || clavePrivada == null) {
            throw new RuntimeException("Error: No se ha generado ninguna clave.");
        }
		
		// ALMACENAR EN EL FORMATO PKCS8 para Privada y PKI para publica
		PrivateKeyInfo        clavePrivadaPKCS8 = gc.getClavePrivadaPKCS8(clavePrivada);
		SubjectPublicKeyInfo  clavePublicaPKI   = gc.getClavePublicaSPKI(clavePublica);
		
		if (clavePrivadaPKCS8 == null || clavePublicaPKI == null) {
            throw new RuntimeException("Error: No se ha cambiado de formato.");
        }
		
		// EN VEZ DE PONER GestionObjetosPEM.escribirObjetoPEM se puede instanciar un objeto de la clase GestionObjetosPEM
		// NO SE PUEDE INSTANCIAR PORQUE ES STATIC
		// Escribir las claves en un fichero en formato PEM 
		GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.PKCS8KEY_PEM_HEADER, clavePrivadaPKCS8.getEncoded(), fichClavePrivada);
		GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.PUBLICKEY_PEM_HEADER, clavePublicaPKI.getEncoded(), fichClavePublica);
		
		
    }



	
	/**
	 * Método que genera una petición de certificado en formato PEM, almacenando esta petición en un fichero.
	 * @param fichPeticion: String con el nombre del fichero donde se guardará la petición de certificado
	 * @throws IOException 
	 * @throws OperatorCreationException 
	 */
	public void crearPetCertificado(String fichPeticion) throws OperatorCreationException, IOException {
		// IMPLEMENTAR POR EL ESTUDIANTE
 
		GestionClaves gc = new GestionClaves (); // Lo utilizamos para pasar las claves a su formato correspondiente
		
		// Verificar que el usuario tiene generadas las claves (leer las claves de los ficheros, o no hace falta porque lo tengo como atributo)
		if (clavePublica != null && clavePrivada != null) {
			
			// 2. Generar nombre x500 del propietario ("C=ES, O=DTE, CN=NOMBRE") 
			//  A que se refiere 
			String x500String = "C=ES, O=DTE, CN=PEPE";
			
			// Crear el objeto X500Name con la información
	        X500Name x500Name = new X500Name(x500String);
			
	        // Imprimir el resultado
	        System.out.println("X500Name generado: " + x500Name.toString());
	        
			// Configurar los parametros del certificado
	        // ALMACENAR EN EL FORMATO PKCS8 para Privada y PKI para publica
			PrivateKeyInfo        clavePrivadaPKCS8 = gc.getClavePrivadaPKCS8(clavePrivada);
			SubjectPublicKeyInfo  clavePublicaPKI   = gc.getClavePublicaSPKI(clavePublica);
			
			// Introducimos por parametro al constructor de la clase PKCS10CertificationRequestBuilder, NOMBRE (x500Name) y CLAVE PUBLICA (SubjectPublicKeyInfo)
	        PKCS10CertificationRequestBuilder peticion = new PKCS10CertificationRequestBuilder(x500Name, clavePublicaPKI); 
	   	
	        //Configurar e instanciar builder para la firma
	        DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new 
					DefaultSignatureAlgorithmIdentifierFinder(); // FIRMA
			DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new 
					DefaultDigestAlgorithmIdentifierFinder();    // RESUMEN
			
			AlgorithmIdentifier sigAlgId = sigAlgFinder.find("SHA256withRSA"); 
			AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId); 
			
			BcContentSignerBuilder csb= new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
			
			// La solicitud se firma con la clave privada del usuario y se escribe en fichPeticion en formato PEM
			PKCS10CertificationRequest pet = peticion.build(csb.build(this.clavePrivada));
			 
			// Guardar en el fichero que se pasa como parametro y en formato PEM
			GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.PKCS10_PEM_HEADER, pet.getEncoded(), fichPeticion);
		
		}else {
			System.out.println("Las claves no han sido generadas. TECLEE 1, para generar las claves");
		}
		
		
		
	}
	
	
	/**
	 * Método que verifica un certificado de una entidad.
	 * @param fichCertificadoCA: String con el nombre del fichero donde se encuentra el certificado de la CA
	 * @param fichCertificadoUsu: String con el nombre del fichero donde se encuentra el certificado de la entidad
     	 * @throws CertException 
	 * @throws OperatorCreationException 
	 * @throws IOException 
	 * @throws FileNotFoundException 	
	 * @return boolean: true si verificación OK, false en caso contrario.
	 */
    public boolean verificarCertificadoExterno(String fichCertificadoCA, String fichCertificadoUsu)throws OperatorCreationException, CertException, FileNotFoundException, IOException {

    	boolean valido = false;
    	boolean fechaValida = false;
    	boolean firmaValida = false;
    	
    	// Leer el fichero Certificado del usuario
    	// LEER OBJETO PEM devuelve una clase objeto (asignamos el objeto que se considere oportuno en cada caso)
    	X509CertificateHolder certUsuario = (X509CertificateHolder) GestionObjetosPEM.leerObjetoPEM(fichCertificadoUsu);
    	
	// Comprobar fecha validez del certificado
    	Date fechaInicio    = certUsuario.getNotBefore();   // Devuelve la fecha de validez del certificado
    	Date fechaExpiracion = certUsuario.getNotAfter();    // Devuelve la fecha de expiración del certificado
    	
    	Date fecha = new Date(System.currentTimeMillis());
		System.out.println("Fecha actual...:"+fecha.toString()); // Momento actual
		
		// compareTo devuelve un 0 si son iguales, + si fecha actual es posterior a la otra fecha, - si la fecha actual es anterior a la otra fecha
		int IniCheck = fecha.compareTo(fechaInicio);         // DEBERIA DAR POSITIVO, fecha actual posterior a la fechaInicio
		int ExpCheck = fecha.compareTo(fechaExpiracion);     // DEBERIA DAR NEGATIVO, fecha actual anterior a la fechaExpiracion
			
		// COMPROBAR SI SE CUMPLEN DICHAS EXPECIFICACIONES
		if(IniCheck > 0 && ExpCheck < 0) {
			fechaValida = true;            // fecha valida
		}else {
			fechaValida = false;
			System.out.println("ERROR: el certificado esta fuera de la fecha de validez");
			//throw new IllegalStateException("Error: El certificado esta fuera de la fecha de validez");
		}
		
		// VERIFICAR LA FIRMA
		// 1. Leer el fichero donde se encuentra el certificado de la CA
		X509CertificateHolder certCA = (X509CertificateHolder) GestionObjetosPEM.leerObjetoPEM(fichCertificadoCA);
		
		// Instanciar un objeto de la clase GestionClaves
		GestionClaves gc = new GestionClaves ();
		
		// 2. Obtener la clave PUBLICA en formato RSAKeyParameters
		RSAKeyParameters clavePublicaCA = gc.getClavePublicaMotor(certCA.getSubjectPublicKeyInfo());     // Nos devuelve la clave publica de CA
			
    	// 3. Generar un contenedor para la verificación
		DefaultDigestAlgorithmIdentifierFinder signer = new DefaultDigestAlgorithmIdentifierFinder();
		ContentVerifierProvider contentVerifierProvider = new BcRSAContentVerifierProviderBuilder(signer).build(clavePublicaCA);
		
		// 4. VERIFICAR FIRMA
		firmaValida = certUsuario.isSignatureValid(contentVerifierProvider);

		if(!firmaValida) 
			System.out.println("ERROR: la firma no ha sido validada");
			//throw new IllegalStateException("Error: No se ha verificado la firma");
		
    	// VERIFICAR SI EL CERTIFICADO ES VALIDO
		if (fechaValida && firmaValida)
			valido = true;
    	
    	
    	return valido;
  		
	}	
}

	// EL ESTUDIANTE PODRÁ CODIFICAR TANTOS MÉTODOS PRIVADOS COMO CONSIDERE INTERESANTE PARA UNA MEJOR ORGANIZACIÓN DEL CÓDIGO