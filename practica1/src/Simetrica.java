package cripto_sim_asim;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.X923Padding;
import org.bouncycastle.crypto.params.KeyParameter;
import java.io.*;
import java.security.SecureRandom;

public class Simetrica {
	
	public void cifrarSimetrica (String ficheroClave, String ficheroACifrar, String ficheroCifrado) throws IOException, DataLengthException, IllegalStateException, InvalidCipherTextException{
		
		// atributos: arrays E/S, motor, etc
		int leidos;
		
		// Crear o sobrescribir en el fichero Clave y se prepara el flujo para escribir datos de forma optima
		BufferedReader lectorClave = new BufferedReader(new FileReader (ficheroClave));
		
		// 1. Leer clave y decodificar Hex
		byte [] clave = Hex.decode(lectorClave.readLine());
		lectorClave.close();
		
		if (clave == null) {
	        throw new IOException("El fichero de clave está vacío.");
	    }
		
		// 2. Generar parametros y cargar clave
		KeyParameter parametros = new KeyParameter(clave);
		
		// 3. Crear motor de cifrado
		PaddedBufferedBlockCipher cifrador = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new X923Padding());

		int tamBlock =cifrador.getBlockSize();
		byte [] datosLeidos = new byte[cifrador.getBlockSize()];
		byte [] datosCifrados = new byte[cifrador.getOutputSize(cifrador.getBlockSize())];
		
		// 4.Iniciar motor
		cifrador.init(true, parametros);
		
		// 5.Crear flujos E/S
		BufferedInputStream lectorDatos = new BufferedInputStream(new FileInputStream(ficheroACifrar));
        BufferedOutputStream escritorDatos = new BufferedOutputStream(new FileOutputStream(ficheroCifrado));
        
        
        // 6. bucle lectura, cifrado y escritura
        //      leer bloque de datos
        //      mientras se hayan leido datos, hace:
        //              cifra bloque(processBytes)
        //				escribir bloque
        //				leer nuevo bloque de datos
        //     cifrar el ultimo bloque(doFinal)
        //     escribir bloque
        
        leidos = lectorDatos.read(datosLeidos, 0, cifrador.getBlockSize());
        while(leidos>0) {
        	int cifrados = cifrador.processBytes(datosLeidos, 0, leidos, datosCifrados, 0);
        	escritorDatos.write(datosCifrados, 0, cifrados);
        	leidos = lectorDatos.read(datosLeidos, 0, tamBlock);
        }	
        
        int block_fin = cifrador.doFinal(datosCifrados, 0);
        escritorDatos.write(datosCifrados, 0, block_fin);
        
        // 7. Cerrar ficheros
        lectorDatos.close();
        escritorDatos.close();
        
	}
	
	public void descifrarSimetrica(String ficheroClave, String ficheroCifrado, String ficheroDescifrado) throws IOException, DataLengthException, IllegalStateException, InvalidCipherTextException{
		
		// atributos: arrays E/S, motor, etc
		int leidos;
		
		// Crear o sobrescribir en el fichero Clave y se prepara el flujo para escribir datos de forma optima 
		BufferedReader lectorClave = new BufferedReader(new FileReader (ficheroClave));
		
		// 1. Leer clave y decodificar Hex
		byte [] clave = Hex.decode(lectorClave.readLine());
        lectorClave.close();
        
		if (clave == null) {
	        throw new IOException("El fichero de clave está vacío.");
	    }
		
		// 2. Generar parametros y cargar clave
		KeyParameter parametros = new KeyParameter(clave);
		
		// 3. Crear motor de cifrado con los datos del enunciado
		PaddedBufferedBlockCipher cifrador = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new X923Padding());

		int tamBlock =cifrador.getBlockSize();
		byte [] datosLeidos = new byte[cifrador.getBlockSize()];
		byte [] datosCifrados = new byte[cifrador.getOutputSize(cifrador.getBlockSize())];
		
		// 4.Iniciar motor
		cifrador.init(false, parametros);
		
		// 5.Crear flujos E/S
		BufferedInputStream lectorDatos = new BufferedInputStream(new FileInputStream(ficheroCifrado));
        BufferedOutputStream escritorDatos = new BufferedOutputStream(new FileOutputStream(ficheroDescifrado));
        
        
        // 6. bucle lectura, cifrado y escritura
        //      leer bloque de datos
        //      mientras se hayan leido datos, hace:
        //              cifra bloque(processBytes)
        //				escribir bloque
        //				leer nuevo bloque de datos
        //     cifrar el ultimo bloque(doFinal)
        //     escribir bloque
        
        leidos = lectorDatos.read(datosLeidos, 0, cifrador.getBlockSize());
        while(leidos>0) {
        	int cifrados = cifrador.processBytes(datosLeidos, 0, leidos, datosCifrados, 0);
        	escritorDatos.write(datosCifrados, 0, cifrados);
        	leidos = lectorDatos.read(datosLeidos, 0, tamBlock);
        }	
        
        int block_fin = cifrador.doFinal(datosCifrados, 0);
        escritorDatos.write(datosCifrados, 0, block_fin);
        
        // 7. Cerrar ficheros
        lectorDatos.close();
        escritorDatos.close();
		
	}
	
	
	public void generar_clave(String fichero) {
		BufferedOutputStream fich_clave= null;
		
		try {
		
			// Crear un objeto de la clase CipherKeyGenerator
			CipherKeyGenerator gen_clave = new CipherKeyGenerator(); 
			
			// Inicialización de objeto generador
			gen_clave.init(new KeyGenerationParameters(new SecureRandom(), 256));		
		
			// Generar una clave
			byte[] clave = gen_clave.generateKey();
			
			// Verificar que la clave no es nula ni vacía
			if (clave == null || clave.length == 0) {
	            throw new RuntimeException("Error: No se ha generado ninguna clave.");
	        }
			
			// Convertir clave a Hexadecimal
			byte[] clave_H = Hex.encode(clave);
			
			fich_clave = new BufferedOutputStream(new FileOutputStream(fichero));
			fich_clave.write(clave_H);                                // Generar clave cual es su longitud
			
			// Asegurar que se escribe completamente antes de cerrar
	        fich_clave.flush();

	        System.out.println("Clave generada y guardada correctamente en " + fichero);
			
		} catch (FileNotFoundException e){ 
			System.err.println("Error: No se puede abrir el fichero " + fichero);
			e.printStackTrace();   
		} catch (IOException e) {
			System.err.println("Error de escritura en el fichero.");
			e.printStackTrace();   
		}
		finally {
			if (fich_clave != null)
				try {
					fich_clave.close();
				} catch (IOException e) {
					System.err.println("Error al cerrar el fichero.");
					e.printStackTrace(); 
				}
		}
	}

}
