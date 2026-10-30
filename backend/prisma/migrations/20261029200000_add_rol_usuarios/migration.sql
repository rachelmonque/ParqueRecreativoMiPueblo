-- Agrega el campo de autorización por rol que faltaba en usuarios (ver PoC1:
-- Falta de Autorización / Escalación de Privilegios, módulo Cliente).
-- Todas las cuentas existentes quedan en "cajero" (menor privilegio) por
-- defecto; promover manualmente a "admin" a quien corresponda después de
-- aplicar esta migración.
ALTER TABLE "usuarios" ADD COLUMN "rol" VARCHAR(20) NOT NULL DEFAULT 'cajero';

-- Enum a nivel de base de datos (defensa en profundidad, mismo patrón que
-- "estado" en clientes/paquetes).
ALTER TABLE "usuarios" ADD CONSTRAINT "chk_usuarios_rol" CHECK ("rol" IN ('admin','cajero'));