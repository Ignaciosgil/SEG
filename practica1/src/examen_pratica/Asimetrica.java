package examen_pratica;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

//import org.bouncycastle.jce.provider.BouncyCastleProvider;     // Esto permite que Java utilice los algoritmos de cifrado, firmas y generación de claves que proporciona Bouncy Castle.
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;        // Clase para crear par de claves publica y privada
import org.bouncycastle.crypto.Digest;                         // Generar el resumen
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;             // Clase para generar el resume
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;

public class Asimetrica {
	
	/**
	 *  Recibe nombre de los ficheros para guardar la clave pública
 	 *  y la privada
	 * 		1. Generación parámetros para inicializar el generador
	 * 		de claves
	 * 		2. Instanciar el generador de claves
	 * 		3. Inicializarlo
	 * 		4. Generar claves
	 * 		5. Obtener clave privada y pública
	 * 		6. Guardar cada clave en un fichero
	 **/
	
	public void generar_clave(String ficheroKs, String ficheroKp) throws FileNotFoundException {     // ficheroKs clave privada || ficheroKp clave publica
		// Generacion de parametros para inicializaar el generador de claves
		RSAKeyGenerationParameters parametros = 
				 new RSAKeyGenerationParameters(BigInteger.valueOf(17), 
				 new SecureRandom(), 2048, 10);
		
		// Instanciar generador de claves
		RSAKeyPairGenerator generadorClaves = new RSAKeyPairGenerator();
		
		// Iniciar generador de claves
		generadorClaves.init(parametros);
		
		// Generar claves (publica y privada)
		
		AsymmetricCipherKeyPair claves = generadorClaves.generateKeyPair();
		
		// Obtener clave privada y clave publica
		RSAKeyParameters clavePublica = (RSAKeyParameters) claves.getPublic();
        RSAKeyParameters clavePrivada = (RSAKeyParameters) claves.getPrivate();
        
        if (clavePublica == null || clavePrivada == null) {
            throw new RuntimeException("Error: No se ha generado ninguna clave.");
        }

        // Mostrar claves
        System.out.println("Clave pública: " + clavePublica.getModulus().toString(16));
        System.out.println("Clave privada: " + clavePrivada.getExponent().toString(16));
		
       try {
    	   // Escribir en el fichero la CLAVE PRIVADA
    	   PrintWriter fClavePrivada = new PrintWriter(new FileWriter(ficheroKs));
    	   fClavePrivada.println(new String (Hex.encode(clavePrivada.getModulus().toByteArray())));
    	   fClavePrivada.print(new String (Hex.encode(clavePrivada.getExponent().toByteArray())));
    	   fClavePrivada.flush();
    	   System.out.println("Clave privada generada y guardada correctamente en " + ficheroKs);
    	   fClavePrivada.close();  // fichero clave privada te guarda la publica y la privada
    	   
    	   
    	   // Escribir en el fichero la CLAVE PUBLICA
    	   PrintWriter fClavePublica = new PrintWriter(new FileWriter(ficheroKp));
    	   fClavePublica.println(new String (Hex.encode(clavePublica.getModulus().toByteArray())));
    	   fClavePublica.print(new String (Hex.encode(clavePublica.getExponent().toByteArray())));
    	   fClavePrivada.flush();
    	   System.out.println("Clave publica generada y guardada correctamente en " + ficheroKp);
    	   fClavePublica.close();
    	   
    	   } catch (FileNotFoundException e) {
    		   System.err.println("Error: No se puede abrir el fichero " + ficheroKs);
    		   System.err.println("Error: No se puede abrir el fichero " + ficheroKp);
    		   e.printStackTrace();
    	   } catch (IOException e) {
    		   System.err.println("Error de escritura en el fichero.");
    		   e.printStackTrace();
    	   }
	}
	
	/**
	 Recibe el tipo de clave con el que se cifra, nombre de los dos 
	 ficheros que contienen la clave de cifrado y el fichero a 
	 cifrar y otro nombre de fichero para dejar el documento cifrado
	  1. Leer el modulo y el exponente de la clave
	  2. Generación parámetros para inicializar el cifrador
	  3. Instanciar el cifrador
	  4. Inicializarlo
	  5. Leer bloques del fichero a cifrar e ir cifrando
	 * @throws IOException 
	 * @throws InvalidCipherTextException 
	**/
	
	public void cifrarAsimetrica(String ficheroClave, String ficheroACifrar, String ficheroCifrado, String tipo) throws IOException, InvalidCipherTextException {
		
		// Leer el modulo y el exponente de la clave
		BufferedReader lectorClave = new BufferedReader(new FileReader(ficheroClave));
		BigInteger modulo = new BigInteger(Hex.decode(lectorClave.readLine()));
		BigInteger exponente = new BigInteger(Hex.decode(lectorClave.readLine()));
		
		// Generacion parametros para inicializar el cifrador CIFRADOR CON CLAVE PRIVADA
		//String tipo = "privada";    // String tipo = "publica"
		RSAKeyParameters parametros = new RSAKeyParameters(tipo.equals("privada"), modulo, exponente); // true privada false publica
		/**Se descifra con la opuesta**/
		
		// Crear el motor de cifrado y descifrado
		AsymmetricBlockCipher cifrador = new PKCS1Encoding(new RSAEngine());
		
		// Iniciar motor (true = cifrar, false = descifrar)
		cifrador.init(true, parametros);
		
		// 5.Crear flujos E/S
		BufferedInputStream lectorDatos = new BufferedInputStream(new FileInputStream(ficheroACifrar));
		BufferedOutputStream escritorDatos = new BufferedOutputStream(new FileOutputStream(ficheroCifrado));
		
		// Leer bloques del fichero a cifrar e ir cifrando
		int tamBlock = cifrador.getInputBlockSize();       // tamaño del bloque de entrada
		byte [] datosLeidos = new byte[tamBlock]; // tamaño de los bloques
		int leidos = lectorDatos.read(datosLeidos, 0, tamBlock);
		while(leidos > 0) {
			byte[] datosCifrados = cifrador.processBlock(datosLeidos, 0, leidos);     // Me devuelve 256 bits(añade 11)
			escritorDatos.write(datosCifrados, 0, datosCifrados.length);
			leidos = lectorDatos.read(datosLeidos, 0, tamBlock);
		}
		
		// No hace falta bloque final doFinal
		
		// 7. Cerrar ficheros
        lectorDatos.close();
        escritorDatos.close();
        lectorClave.close();
		
	}
	
	/**
	 Recibe el tipo de clave con el que se cifra, nombre de los dos 
	 ficheros que contienen la clave de cifrado y el fichero a 
	 cifrar y otro nombre de fichero para dejar el documento cifrado
	  1. Leer el modulo y el exponente de la clave
	  2. Generación parámetros para inicializar el cifrador
	  3. Instanciar el cifrador
	  4. Inicializarlo
	  5. Leer bloques del fichero a cifrar e ir cifrando
	 * @throws IOException 
	 * @throws InvalidCipherTextException 
	**/
	
    public void descifrarAsimetrica(String ficheroClave, String ficheroCifrado, String ficheroDescifrado, String tipo) throws IOException, InvalidCipherTextException {
    	
    	// Leer el modulo y el exponente de la clave
		BufferedReader lectorClave = new BufferedReader(new FileReader(ficheroClave));
		BigInteger modulo = new BigInteger(Hex.decode(lectorClave.readLine()));
		BigInteger exponente = new BigInteger(Hex.decode(lectorClave.readLine()));
		
		// Generacion parametros para inicializar el cifrador CIFRADOR CON CLAVE PRIVADA
		//String tipo = "publica";    // String tipo = "publica"       AÑADIRLO EN LA FUNCION  COMO PARAMETRO
		RSAKeyParameters parametros = new RSAKeyParameters(tipo.equals("privada"), modulo, exponente); // true privada false publica
		/**Se descifra con la opuesta, a la que se cifra**/
		
		// Crear el motor de cifrado y descifrado
		AsymmetricBlockCipher cifrador = new PKCS1Encoding(new RSAEngine());
		
		// Iniciar motor (true = cifrar, false = descifrar)
		cifrador.init(false, parametros);
		
		// Crear flujos E/S
		BufferedInputStream lectorDatos = new BufferedInputStream(new FileInputStream(ficheroCifrado));
		BufferedOutputStream escritorDatos = new BufferedOutputStream(new FileOutputStream(ficheroDescifrado));
		
		// Leer bloques del fichero a cifrar e ir cifrando
		int tamBlock =cifrador.getInputBlockSize();
		int leidos;
		byte [] datosLeidos = new byte[tamBlock]; // tamaño de los bloques
		
		// Al menos tiene que entrar una vez en el bucle
		while((leidos = lectorDatos.read(datosLeidos, 0, tamBlock)) > 0) {
			byte[] datosCifrados = cifrador.processBlock(datosLeidos, 0, leidos);     // Me devuelve 256 bits(añade 11)
			escritorDatos.write(datosCifrados, 0, datosCifrados.length);
			leidos = lectorDatos.read(datosLeidos, 0, tamBlock);
		}
        
        // 7. Cerrar ficheros
        lectorDatos.close();
        escritorDatos.close();
        lectorClave.close();
		
	}
    
    /**
     * 
     * Recibe tres nombres de ficheros: nombre del fichero que
	 * contiene la clave privada, el fichero con el mensaje en claro
	 * a enviar y el fichero para dejar la firma (hay otro fichero
	 * intermedio, donde se dejará el resumen)
	 * 		1. Instanciar la clase para generar el resumen
	 * 		2. Generar el resumen
	 * 		3. Cifrar el resumen
     * @throws IOException 
     * @throws InvalidCipherTextException 
    **/
    
    public void firma_digital(String ficheroClave, String ficheroACifrar, String ficheroFirma) throws IOException, InvalidCipherTextException {
    	
    	// Instanciar la clase para generar el resumen
    	Digest resumen = new SHA1Digest();
    	
    	// 5.Crear flujos E/S
    	BufferedInputStream lectorDatos = new BufferedInputStream(new FileInputStream(ficheroACifrar));
    	BufferedOutputStream escritorDatos = new BufferedOutputStream(new FileOutputStream("fichero_Resumen.txt"));
    	
    	int tamBlock =resumen.getDigestSize();
    	
    	byte [] datosLeidos = new byte[tamBlock];
    	//byte [] datosEscritos = new byte[tamBlock];
    	
    	int leidos;
    	
        while((leidos = lectorDatos.read(datosLeidos, 0, tamBlock))>0) {
        	resumen.update(datosLeidos, 0, leidos);
        	leidos = lectorDatos.read(datosLeidos, 0, tamBlock);
        }	
        
        byte [] block_fin = new byte [tamBlock];
        resumen.doFinal(block_fin, 0);
        escritorDatos.write(block_fin, 0, tamBlock);
        lectorDatos.close();
        escritorDatos.close();
        
        // IMPORTANTE: cerrar los ficheros antes de cifrar y descifrar
        
        // Cifrar ficheros de forma asimetrica
        cifrarAsimetrica(ficheroClave, "fichero_Resumen.txt", ficheroFirma, "privada");
        System.out.println("El fichero '"+ficheroFirma+"' ha sido firmado");
    }

    
    /**
     * 
     * Recibe tres nombres de ficheros: nombre del fichero que contiene la
	 * clave publica, el fichero con el mensaje en claro recibido y el
	 * fichero que contiene la firma
	 *	1. Descifrar el fichero de la firma para obtener el resumen
	 *	2. Generar el resumen del fichero en claro
	 *	3. Si son iguales, la firma se ha verificado
     * @throws IOException 
     * @throws InvalidCipherTextException 
     * 
     * 
    **/
    public boolean verificarFirma(String ficheroClave, String ficheroEnClaro, String ficheroFirma) throws InvalidCipherTextException, IOException {
    	boolean verificado = false;
    	// Instanciar la clase para generar el resumen
    	Digest resumen = new SHA1Digest();
    	int tamBlock =resumen.getDigestSize();
    	
    	descifrarAsimetrica(ficheroClave, ficheroFirma, "ficheroFirma_Des.txt", "publica");
    	BufferedInputStream lectorcifradoFirma = new BufferedInputStream(new FileInputStream("ficheroFirma_Des.txt"));
    	byte [] firmadoHash = new byte[tamBlock];
    	lectorcifradoFirma.read(firmadoHash);
    	
    	// Crear flujos E/S
    	BufferedInputStream lectorDatos = new BufferedInputStream(new FileInputStream(ficheroEnClaro));
    	//BufferedOutputStream escritorDatos = new BufferedOutputStream(new FileOutputStream("fichero_Resumen.txt"));
    	
    	byte [] datosEnClaro = new byte[tamBlock];
    	//byte [] datosEscritos = new byte[tamBlock];
    	
    	int leidos;
    	
        while((leidos = lectorDatos.read(datosEnClaro, 0, tamBlock))>0) {
        	resumen.update(datosEnClaro, 0, leidos);
        	leidos = lectorDatos.read(datosEnClaro, 0, tamBlock);
        }	

        resumen.doFinal(datosEnClaro, 0);
        //escritorDatos.write(descifradoHash, 0, tamBlock);
        
        lectorcifradoFirma.close();
        lectorDatos.close();
        //escritorDatos.close();
        
        verificado = Arrays.equals(firmadoHash, datosEnClaro);
     // Mostrar claves
        System.out.println("Firma descifrada " + firmadoHash);
        System.out.println("Firma descifrada " + datosEnClaro);
        if(verificado)
         System.out.println("FIRMA VERIFICADA.\n");
        else
         System.out.println("No se ha encontrado la firma, los fichero no son difrentes.\n");
    	
    	return verificado;
    	
    }
}
