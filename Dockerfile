# Usa una imagen base de Bun
FROM oven/bun:1.0.2

# Establece la carpeta de trabajo dentro del contenedor
WORKDIR /app

# Copia los archivos necesarios para instalar dependencias
COPY package.json bun.lock ./

# Instala las dependencias con Bun
RUN bun install --frozen-lockfile

# Copia el código fuente al contenedor
COPY . .

# Expone el puerto (ajústalo si usas otro)
EXPOSE 3000

# Comando para iniciar la app
CMD ["bun", "dev"]
