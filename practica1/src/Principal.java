package cripto_sim_asim;
/**Fichero: Principal.java
 * Clase para comprobar el funcionamiento de las otras clases del paquete.
 * Asignatura: SEG
 * @author Profesores de la asignatura
 * @version 1.0
 */

import java.io.IOException;
import java.util.Scanner;
//import java.io.File;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;

public class Principal {

	public static void main (String [ ] args) throws DataLengthException, IllegalStateException, InvalidCipherTextException, IOException {
		int menu1;
		int menu2;
		Scanner sc = new Scanner(System.in);
		/* completar declaracion de variables e instanciación de objetos */
		//File archivo = new File("fichero_clave.txt");
		Simetrica  sim   = new Simetrica();
		Asimetrica asim = new Asimetrica();
		
		do {
			System.out.println("¿Qué tipo de criptografía desea utilizar?");
			System.out.println("1. Simétrico.");
			System.out.println("2. Asimétrico.");
			System.out.println("3. Salir.");
			menu1 = sc.nextInt();
		
			switch(menu1){
				case 1:
					do{
						System.out.println("Elija una opción para CRIPTOGRAFIA SIMÉTRICA:");
						System.out.println("0. Volver al menú anterior.");
						System.out.println("1. Generar clave.");
						System.out.println("2. Cifrado.");
						System.out.println("3. Descifrado.");
						menu2 = sc.nextInt();
				
						switch(menu2){
							case 1:
								System.out.println("Nombra fichero donde se generará la clave: ");
								String fichero_clave=sc.next();
								sim.generar_clave(fichero_clave);    // Generar la clave
							break;
							case 2:
								System.out.println("Nombra al fichero de la clave: ");
								String ficheroClave = sc.next();
								System.out.println("Indica nombre del fichero a cifrar: ");
								String ficheroACifrar = sc.next();
								System.out.println("Nombra como se llama el fichero cifrado: ");
								String ficheroCifrado = sc.next();
								sim.cifrarSimetrica(ficheroClave, ficheroACifrar, ficheroCifrado);         // Cifrar el documento
							break;
							case 3:
								System.out.println("Indica nombre del fichero clave: ");
								ficheroClave = sc.next();
								System.out.println("Indica nombre del fichero cifrado: ");
								ficheroCifrado = sc.next();
								System.out.println("Nombra como se llamara el fichero descifrado: ");
								String ficheroDesCifrado = sc.next();
								sim.descifrarSimetrica(ficheroClave, ficheroCifrado, ficheroDesCifrado);  // Descifrar el documento
							break;
						}
					} while(menu2 != 0);
				break;
				case 2:
					do{
						System.out.println("Elija una opción para CRIPTOGRAFIA ASIMÉTRICA:");
						System.out.println("0. Volver al menú anterior.");
						System.out.println("1. Generar clave.");
						System.out.println("2. Cifrado.");
						System.out.println("3. Descifrado.");
						System.out.println("4. Firmar digitalmente.");
						System.out.println("5. Verificar firma digital.");
						menu2 = sc.nextInt();
				
						switch(menu2){
							case 1:
								System.out.println("Nombra al fichero de la clave publica: ");
								String kPublica = sc.next();
								System.out.println("Nombra al fichero de la clave clave privada: ");
								String kPrivada = sc.next();
								asim.generar_clave(kPrivada, kPublica);
							break;
							case 2:
								String tipoClave = null;
								String nomFicheroClave = null;
								int opcion;
								/*completar acciones*/
								System.out.println("Escoge que tipo de clave usaras para cifrar:");
								System.out.println("1.Publica");
								System.out.println("2.Privada");
								opcion=sc.nextInt();
								switch(opcion) {
									case 1:
										tipoClave = "publica";
										System.out.println("\nIndica nombre del fichero que tiene la clave privada: ");
										nomFicheroClave = sc.next();
									break;
									case 2:
										tipoClave = "privada";
										System.out.println("\nIndica nombre del fichero que tiene la clave privada: ");
										nomFicheroClave = sc.next();
									break;
									default:
								}
								System.out.println("\nIndica nombre del fichero a cifrar: ");
								String nomFicheroCifrar = sc.next();
								System.out.println("\nNombra como se llama el fichero cifrado: ");
								String ficheroCifrado = sc.next();
								asim.cifrarAsimetrica(nomFicheroClave, nomFicheroCifrar, ficheroCifrado, tipoClave);
							break;
							case 3:
								System.out.println("Escoge que tipo de clave usaras para descifrar:");
								System.out.println("1. Publica");
								System.out.println("2. Privada");
								opcion=sc.nextInt();
								nomFicheroClave=null;
								tipoClave=null;
								switch(opcion) {
									case 1:
										tipoClave = "publica";
										System.out.println("\nIndica nombre del fichero que tiene la clave publica: ");
										nomFicheroClave = sc.next();
									break;
									case 2:
										tipoClave = "privada";
										System.out.println("\nIndica nombre del fichero que tiene la clave privada: ");
										nomFicheroClave = sc.next();
									default:
								}
								System.out.println("\nIndica nombre del fichero cifrado: ");
								ficheroCifrado = sc.next();
								System.out.println("\nNombra como se llamara el fichero descifrado: ");
								String ficheroDesCifrado = sc.next();
								asim.descifrarAsimetrica(nomFicheroClave, ficheroCifrado, ficheroDesCifrado, tipoClave);
							break;
							case 4:
								System.out.println("Indica fichero con la clave privada:");
								String ficheroClave = sc.next();
								System.out.println("\nIndica nombre del fichero a firmar: ");
								String ficheroAFirmar = sc.next();
								System.out.println("\nNombra donde deja la firma: ");
								String ficheroFirma = sc.next();
								asim.firma_digital(ficheroClave, ficheroAFirmar, ficheroFirma);
							break;
							case 5:
								System.out.println("Indica fichero con la clave publica:");
								ficheroClave = sc.next();
								System.out.println("\nIndica nombre del fichero con los datos: ");
								String ficheroDatos = sc.next();
								System.out.println("\nNombra donde se verifica la firma: ");
								String ficheroVerificar = sc.next();
								asim.verificarFirma(ficheroClave, ficheroDatos, ficheroVerificar);
							break;
						}
					} while(menu2 != 0);
				break;
			}			
		} while(menu1 != 3);
		sc.close();
	}
}
