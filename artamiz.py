#!/usr/bin/python
# -*- coding: utf-8 -*-

# artamiz.py
#       
#  Copyright 2012 Ángel Coto <codiasw@gmail.com>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details (http://www.gnu.org/licenses/gpl.txt)
#  

# Descripción:
# Este programa genera y verifica tablas hash para directorios.

# Historial de versión
# 2.0.0: Incorpora la opción de elegir el algoritmo de cálculo
#        Incorpora algoritmo CRC32
# 2.0.1: Corrige un error.  Cuando se usaba con la opción '-te' se envíaba 'ar1' como parámetro a la
#        función 'calcsum', cuando lo correcto es ar2.  Esto daba como resultado un hash constante.
# 2.0.2: Valida cuando un directorio no puede ser accedido.  Produce el error 15.

import hashlib, zlib, os
from sys import argv
from getpass import getuser
from time import localtime, strftime

### Define la versión del programa
ver = '2.0.2'

### Función que imprime en pantalla ayuda sobre el uso del programa
def hintdeuso():
	programa = os.path.basename(argv[0]) #Extrae el nombre del programa (tiene utilidad en Windows)
	print('\n {0} {1}.'.format(programa,ver))
	print(' Copyright (c) 2012-2013 Ángel Coto <codiasw@gmail.com>.\n')
	print(' Calcula y verifica valores hash para archivos.  Algoritmo por defecto es sha256.')
	print(' Puede especificar opcionalmente crc32, md5 ó sha1.\n')
	print(' Uso: python {0} ?'.format(programa))
	print('                        <archivo> [crc32|md5|sha1]')
	print('                        -te <texto> [crc32|md5|sha1]')
	print('                        -da [crc32|md5|sha1]')
	print( '                        -de <directorio> [crc32|md5|sha1]')
	print('                        -der <directorio> [crc32|md5|sha1]')
	print('                        -co <archivo1> <archivo2>')
	print('                        -ve <archivo> <directorio>')
	print('                        -ver <archivo>\n')
	print('      Opciones:')
	print('''                 ?: Muestra esta ayuda. La ayuda también se muestra cuando se 
                    ejecuta el programa sin argumento de entrada.''')
	print('         <archivo>: Muestra el hash de <archivo>.')
	print('           (*) -te: Calcula hash para <texto>.')
	print('               -da: Calcula hash para los archivos del directorio actual.')
	print('               -de: Calcula hash para los archivos de <directorio>.')
	print('              -der: Calcula hash para los archivos de <directorio> y de')
	print('                    todos los subdirectorios')
	print('               -co: Compara los hash de <archivo1> y de <archivo2>.')
	print('''               -ve: Verifica los hash de los archivos en <directorio> contra
                    los hash almacenados en <archivo>.''')
	print('              -ver: Verifica los hash de los archivos listados en <archivo>.\n')
	print('''      (*): El hash de textos puede variar entre sistemas dependiendo del código
	   de página del sistema operativo.\n''')
	print(' Este programa es software libre bajo licencia GPLv3.\n')

### Inicializa mensajes de error
error1 = "* Error 1: '{0}' no es comando válido o el directorio no existe."
error2 = "* Error 2: '{0}' no es comando válido o el archivo no existe."
error3 = "* Error 3: '{0}' es un directorio. No se puede calcular hash a un directorio."
error4 = "* Error 4: No se tiene permisos para leer el archivo '{0}'."
error5 = "* Error 5: '{0}' no es un directorio."
error6 = "* Error 6: '{0}' no es un archivo."
error7 = "* Error 7: '{0}' no es un argumento esperado."
error8 = "* Error 8: Debe especificar un directorio."
error9 = "* Error 9: Debe especificar los dos archivos a comparar."
error10 = '''* Error 10: Debe especificar el archivo que contiene los valores hash
            y el directorio que contiene los archivos a verificar.'''
error11 = "* Error 11: '{0}' no tiene líneas con estructura de tabla hash."
error12 = "* Error 12: '{0}' está siendo usado por otro proceso en forma exclusiva o ha sido removido."
error13 = "* Error 13: Debe especificar archivo de tabla hash."
error14 = "* Error 14: Debe especificar cadena de texto."
error15 = "* Error 15: No se puede abrir el directorio {0}."

### Función para imprimir encabezado de tabla de resultados de verificación
def encabezadotablaverif(archivo, directorio, modo):
	print('Resultados generados por: ' + getuser())
	print('Para tabla: ' + archivo + ' ' + calcsum(archivo,'f','sha256'))
	if modo == 'e':
		print('Contra directorio: ' + directorio)
	print('Inicio: ' + strftime("%d/%m/%Y - %H:%M:%S", localtime()))
	print('----------------------------------------------------------------')
	print('ARCHIVO\tRESULTADO\tMENSAJE')

### Función para imprimir encabezado de tabla hash
def encabezadotablahash(directorio, algoritmo):
	print('Tabla hash (' + algoritmo + ') generada por: ' + getuser())
	print('Para: ' + directorio)
	print('Inicio: ' + strftime("%d/%m/%Y - %H:%M:%S", localtime()))
	print('----------------------------------------------------------------')

### Función para imprimir el pie de informe
def piedeinforme():
	print('----------------------------------------------------------------')
	print('Fin: ' + strftime("%d/%m/%Y - %H:%M:%S", localtime()))

### Función que verifica si una cadena es hexadecimal
#  
#  name: eshex
#  @param: cadena caracter a analizar
#  @return: True si es hexadecimal, False si no lo es
def eshex(valor):
	try:
		entero = int(valor,16)
		conversion = True
	except:
		conversion = False
	return conversion

### Función que detecta si un archivo está bloqueado por otro proceso
#
#  name: enllavado
#  @param: nombre del archivo a verificar
#  @return: True si está bloqueado, False si no lo está
def enllavado(archivo):
	try:
		f = open(archivo,'rb')
		data = f.read(8192)
		f.close()
		return(False)
	except:
		return(True)

def algoritmousado(valor):
	longitud = len(valor)
	if longitud == 64:
		algoritmo = 'sha256'
	elif longitud == 40:
		algoritmo = 'sha1'
	elif longitud == 32:
		algoritmo = 'md5'
	else:
		algoritmo = 'crc32'
	return algoritmo


### Función que calcula el hash para el archivo de entrada
#  
#  nombre: calcsum
#  @param: nombre del objeto a calcular el hash
#          tipo de objeto al cual se calculará hash ('t': texto; 'f': archivo)
#          algorito que se utilizará para calcular el hash
#  @return: hash calculado con algoritmo seleccionado
def calcsum(objeto,tipoobjeto,algoritmo):
	valorhash = 0
	
	if algoritmo == 'crc32':
		if tipoobjeto == 't':
			valorhash = zlib.crc32(objeto)
		else:
			fh = open(objeto,'rb') # Abre lectura en modo binario
			for linea in fh:
				valorhash = zlib.crc32(linea, valorhash)
		valorhash = "%X"%(valorhash & 0xFFFFFFFF) #Almacena el valor hash en hexadecimal

	else:
		if algoritmo == 'sha256':
			m = hashlib.sha256()
		elif algoritmo == 'sha1':
			m = hashlib.sha1()
		else:
			m = hashlib.md5()
		if tipoobjeto == 't':
			m.update(objeto)
		else:
			fh = open(objeto, 'rb') #Abre lectura en modo binario
			while True:
				data = fh.read(8192) #Lee el archivo en bloques de 8Kb
				if not data:
					break
				m.update(data)
			fh.close
		valorhash = m.hexdigest()
		
	return valorhash #Devuelve el valor hash en hexadecimal

### Función que calcula e imprime los hashes para los archivos del directorio especificado    
#  
#  nombre: calcsumdir
#  @param: directorio en el cual están los archivos a los cuale se les calculará hash
#  @return: ninguno
def calcsumdir(ruta,algoritmo):
	errores = []
	error = False
	try:
		listado = os.listdir(ruta) #Extrae el listado de archivos del directorio
	except:
		errores.append(error15.format(ruta))
		error = True
	
	if not error:
	
		listado.sort() #Ordena los elementos de la lista para mejor lectura de la salida
		
		for archivo in listado: #Recorre el listado de elementos en el directorio
			if os.path.isfile(archivo): #Verifica si el elemento es un archivo
				if os.access(archivo,os.R_OK):
					if not enllavado(archivo):
						print(calcsum(archivo,'f',algoritmo)+' *'+archivo)
					else:
						print(error12.format(archivo))
				else:
					 errores.append(error4.format(archivo)) #Incorpora el mensaje de error al listado de errores
			else:
				errores.append(error3.format(archivo))  #Si es directorio solo lo informa
			
	for mensaje in errores:
		print(mensaje)

### Función que calcula e calcula los hashes para los archivos del directorio especificado y de sus subdirectorios
#  
#  nombre: calcsumdirrec
#  @param: directorio en el cual están los archivos a los cuale se les calculará hash
#  @return: ninguno
def calcsumdirrec(ruta, algoritmo):
	
	if os.path.isdir(ruta):
		error = False
		try:
			os.chdir(ruta) # Cambia al directorio
		except:
			print(error15.format(ruta))
			error = True
		
		if not error:
			directorio = os.getcwd()
			try:
				listado = os.listdir(directorio) #Obtiene los elementos del directorio
			except:
				print(error15.format(ruta))
				error = True
				
			if not error:
				for nombre in listado: #Para cada nombre en el listado
					elemento = os.path.join(directorio,nombre) #Construye la ruta completa
					calcsumdirrec(elemento,algoritmo)

	else:
		if os.access(ruta,os.R_OK):
			if not enllavado(ruta):
				linea = calcsum(ruta,'f',algoritmo)+' *'+ruta
			else:
				linea = error12.format(ruta)
		else:
			 linea = (error4.format(ruta)) 
		print(linea)
#		listasalida.append(linea) #Lo agrega en la lista de salida
	return 0

### Función que recorre una archivo hash y verifica los valores del archivo contra archivos de un directorio
#
#  nombre: verificahashes
#  @param: archivo: nombre del archivo de hashes.
#          directorio: donde se ubican los archivos a comparar; solo es útil en modo manual.
#          modo: modalidad de análisis (automático o manual); la modalidad automática busca cada archivo a partir
#                de su pathname, mientras que la manual requiere que se especifique la ruta de los archivos (directorio).
#  @return: ninguno
def verificahashes(archivo, directorio, modo):
	archivohash = open(archivo,'r') 
	lineasprocesadas = False
	encabezadotablaverif(archivo,directorio, modo) 
	
	if modo == 'e': #Si es modo manual cambia al directorio donde están los archivos a verificar
		os.chdir(directorio) 
	
	for linea in archivohash: #Lee el archivo hash línea por línea
							  #Interesa evaluar cada línea para saber si tiene estructura hash file

		elementos = linea.split() #Separa en una lista las partes de la línea
		
		if len(elementos) > 1: #Primer validación: ¿tiene más de un elemento?
		
			if eshex(elementos[0]): #Segunda validación: ¿El primer elemento es hexadecimal?
				
				lineasprocesadas = True
				valorhash = elementos[0] #Valor hash contenido en la línea en curso
				algoritmo = algoritmousado(valorhash)
				
				#Ahora es necesario extraer de la línea el nombre del archivo
				restolinea = linea[len(elementos[0])+1:] #Contiene el nombre del archivo más el caracter de fin de línea
				nombrearchivo = restolinea[:len(restolinea)-1] # Se le retira el fin de línea

				if nombrearchivo[:1] == '*' or nombrearchivo[:1] == ' ':
					nombrearchivo = nombrearchivo[1:] #Quita el '*' o el ' ' al nombre del archivo

				if modo == 'e':
					nombrearchivo = os.path.basename(nombrearchivo) #Si es modo manual analizamos solo el nombre del archivo
					
				if os.path.isfile(nombrearchivo):
					if os.access(nombrearchivo,os.R_OK):
						if valorhash == calcsum(nombrearchivo,'f',algoritmo):
							print(nombrearchivo + '\t OK\tLos valores hash coinciden.')
						else:
							print(nombrearchivo + '\tFALLA\tLos valores hash son diferentes.')
					else:
						print(nombrearchivo + '\tADVERTENCIA\tNo se cuenta con permisos para leer el archivo.')
				else:
					print(nombrearchivo + '\tADVERTENCIA\tNo existe en el directorio especificado.')
					
	if not lineasprocesadas: #No se encontraron líneas de formato válido
		print(error11.format(archivo))
		
	piedeinforme() #Imprime pie de informe

def main():
	### Inicia el programa leyendo el argumento y validándolo
	#
	try: #Verifica si hay al menos un argumento
		ar1 = argv[1]
	except: #Salida por no existir argumento
		hintdeuso()
		exit()

	### Se evalúa el argumento1 para determinar la opción elegida
	if ar1 == '?': #Imprime la ayuda
		hintdeuso()

	elif ar1 == '-da': #Entra si calculará hash para el directorio de trabajo
		error = False
		try: # Busca determianr si hay algoritmo especificado
			ar2 = argv[2] #Si hay un segundo argumento, es un error
			if ar2 <> 'crc32' and ar2 <> 'sha1' and ar2 <> 'md5':
				error = True
				print(error7.format(ar2))
			
		except: # Si no se especificó entonces asigna el algoritmo por defecto
			ar2 = 'sha256'
		
		if not error:
			directorio = os.getcwd() #Captura del directorio de trabajo
			encabezadotablahash(directorio,ar2) #Imprime el encabezado de la salida
			calcsumdir(directorio,ar2) #Calcula los hashes del directorio de trabajo
			piedeinforme()
		
	elif ar1 == '-de' or ar1 == '-der': #Entra si calculará hash para directorio especificado o generación recursiva
		try:
			ar2 = argv[2]
		except: 
			print(error8)
			exit()
			
		if os.path.exists(ar2): #Verifica si el directorio existe
			if os.path.isdir(ar2): #Si el directorio es válido
			
				error = False
				try: # Busca determinar si hay algoritmo especificado
					ar3 = argv[3]
					if ar3 <> 'crc32' and ar3 <> 'sha1' and ar3 <> 'md5':
						error = True
						print(error7.format(ar3))
					
				except: # Si no se especificó entonces asigna el algoritmo por defecto
					ar3 = 'sha256'
				
				if not error:
					os.chdir(ar2)
					directorio = os.getcwd()
					encabezadotablahash(directorio,ar3)
					
					if ar1 == '-de': #Si es generación solo a directorio específico
						calcsumdir(directorio,ar3) #Calcula los hashes del directorio especificado

					else: #Es generación recursiva
						calcsumdirrec(directorio,ar3) # Llama la función de cálculo de hash para directorios recursivos
						
					piedeinforme()
				
			else:
				print(error5.format(ar2))
				
		else: #El directorio no existe
				print(error1.format(ar2))

	elif ar1 == '-co': #Entra si hará una comparación entre dos archivos
		try:
			ar2 = argv[2]
			ar3 = argv[3]
		except:
			print(error9)
			exit()
			
		errorentrada = False
		
		if not os.path.isfile(ar2): #¿Es un archivo?
			print(error6.format(ar2))
			errorentrada = True
			
		else:
			if not os.access(ar2,os.R_OK): #¿Se tiene permisos de lectura?
				print(error4.format(ar2))
				
		if not os.path.isfile(ar3): #¿Es un archivo?
			print(error6.format(ar3))
			errorentrada = True
			
		else:
			if not os.access(ar3,os.R_OK): #¿Se tiene permisos de lectura?
				print(error4.format(ar3))
				
		if not errorentrada:
			hashar2 = calcsum(ar2,'f','sha256')
			hashar3 = calcsum(ar3,'f','sha256')
			if hashar2 == hashar3:
				print('* Resultado: OK. Los valores hash coinciden.')
			else:
				print('* Resultado: FALLA: Los valores hash son diferentes.')
			
	elif ar1 == '-ve': #Entra si hará una verificación de archivo de hashes contra directorio especificado
		try:
			ar2 = argv[2] #Nombre del archivo hash
			ar3 = argv[3] #Directorio de archivos a verificar
		except:
			print(error10)
			exit()
			
		errorentrada = False
		
		if not os.path.isfile(ar2):
			errorentrada = True
			print(error6.format(ar2)) #No es un archivo
			
		if not os.path.isdir(ar3):
			errorentrada = True
			print(error5.format(ar3)) #No es un directorio
			
		if not errorentrada:
			argmodo = 'e'
			verificahashes(ar2, ar3, argmodo)
			
	elif ar1 == '-ver': #Entra si hará una verificación a partir de archivo hash (automático: no requiere espeficación de directorio)
		try:
			ar2 = argv[2] #Nombre del archivo hash
		except:
			print(error13)
			exit()
			
		errorentrada = False
			
		if not os.path.isfile(ar2):
			errorentrada = True
			print(error6.format(ar2)) #No es un archivo
			
		if not errorentrada:
			argmodo = 'a'
			verificahashes(ar2, 'nulo', argmodo)

	elif ar1 == '-te': #Opción de calcular hash para texto en línea de comando
		try:
			ar2 = argv[2] #Texto a procesar
		except:
			print(error14)
			exit()
			
		error = False
		try: # Busca determianr si hay algoritmo especificado
			ar3 = argv[3]
			if ar3 <> 'crc32' and ar3 <> 'sha1' and ar3 <> 'md5':
				error = True
				print(error7.format(ar3))
		except: # Si no se especificó entonces asigna el algoritmo por defecto
			ar3 = 'sha256'
		
		if not error:
			print(calcsum(ar2,'t',ar3))

	else: #Entra si no se especificó argumento.  Calcula hash si es un archivo
		if os.path.exists(ar1): #Verifica si el archivo existe
			if os.path.isfile(ar1):
				if os.access(ar1,os.R_OK): #Verifica si hay permiso de lectura sobre el archivo
					if not enllavado(ar1):
						error = False
						try: # Busca determianr si hay algoritmo especificado
							ar2 = argv[2] #Si hay un segundo argumento, es un error
							if ar2 <> 'crc32' and ar2 <> 'sha1' and ar2 <> 'md5':
								error = True
								print(error7.format(ar2))
						except: # Si no se especificó entonces asigna el algoritmo por defecto
							ar2 = 'sha256'
						if not error:
							print(calcsum(ar1,'f',ar2)+' *'+ar1)
					else:
						print(error12.format(ar1))
				else: #No se tiene permisos de lectura sobre el archivo
					print(error4.format(ar1))
			else: #Resultó ser un directorio. No se puede calcular hash
				print(error3.format(ar1))
		else: #Error: El archivo no existe o es switch inválido
			print(error2.format(ar1))

if __name__ == '__main__':
	main()
else:
	None
