import { z } from 'zod'
import DOMPurify from 'isomorphic-dompurify'
// Máximo representable en Decimal(10,2)
const DEC_MAX = 99_999_999.99

// Fecha en formato ISO/'YYYY-MM-DD' válida.
const fechaISO = z
  .string()
  .refine((s) => /^\d{4}-\d{2}-\d{2}/.test(s) && !Number.isNaN(Date.parse(s)), 'Fecha inválida')

  // Texto libre sanitizado: elimina cualquier etiqueta HTML (incluye <script>,
// <img onerror=...>, etc.) antes de que el dato llegue a persistirse. Se hace
// en el origen para que la protección no dependa de que cada consumidor de
// la API (SPA oficial, dashboards externos, integraciones futuras) escape
// correctamente por su cuenta (defensa en profundidad). Ver PoC2 (XSS Stored
// vía API sin sanitizar, Fase 2).
const textoLibreSanitizado = (maxLen: number) =>
  z
    .string()
    .max(maxLen)
    .nullish()
    .transform((v) => (v ? DOMPurify.sanitize(v, { ALLOWED_TAGS: [] }) : v))

// ---------- Categorías ----------
export const categoriaCreateSchema = z.object({
  nombre: z.string().trim().min(1, 'El nombre es requerido').max(100),
  descripcion: z.string().max(1000).nullish(),
})
export const categoriaUpdateSchema = categoriaCreateSchema.partial()

// ---------- Clientes ----------
export const clienteCreateSchema = z.object({
  nombre: z.string().trim().min(1, 'El nombre es requerido').max(150),
  // La cédula es opcional: hay clientes menores de edad que aún no la tienen.
  // Un valor vacío se guarda como NULL, porque el índice único solo admitiría
  // una fila con la cadena vacía y bloquearía al segundo cliente sin cédula.
  cedula: z.string().trim().max(30).nullish().transform((v) => v || null),
  telefono: z.string().max(30).nullish(),
  fecha_inicio: fechaISO,
  observaciones: textoLibreSanitizado(2000),
  estado: z.enum(['activo', 'inactivo']).default('activo'),
})
export const clienteUpdateSchema = clienteCreateSchema.partial()

// ---------- Paquetes ----------
const paqueteBase = z.object({
  nombre: z.string().trim().min(1, 'El nombre es requerido').max(150),
  // En un paquete de precio abierto el precio es opcional: si viene, sirve de
  // referencia para prellenar la factura; si no, se escribe desde cero.
  precio: z.coerce.number().positive('El precio debe ser mayor a 0').max(DEC_MAX).nullish(),
  precio_abierto: z.boolean().default(false),
  // Paquete de hotel: el importe sale de multiplicar la tarifa por noche por la
  // cantidad de noches, ambas indicadas en la factura. El `precio` del paquete
  // pasa a ser la tarifa por noche por defecto.
  cobro_por_noche: z.boolean().default(false),
  categoria_id: z.coerce.number().int().positive('La categoría es requerida'),
  duracion_dias: z.coerce.number().int().positive('La duración debe ser mayor a 0'),
  duracion_unidad: z.enum(['dias', 'meses']).default('dias'),
  estado: z.enum(['activo', 'inactivo']).default('activo'),
})

type PaqueteModo = { precio_abierto?: boolean; cobro_por_noche?: boolean; precio?: number | null }

// Solo un paquete de precio fijo obliga a tener precio: en los otros dos modos
// el precio se escribe (o se ajusta) al facturar. En un update parcial que no
// toque el modo no hay nada que validar aquí.
const precioSegunModo = (d: PaqueteModo) =>
  d.precio_abierto !== false || d.cobro_por_noche !== false || d.precio != null
const msgPrecio = { path: ['precio'], message: 'El precio es requerido en un paquete de precio fijo' }

// Los modos son excluyentes: el cobro por noche ya ajusta la tarifa en cada factura.
const modosExcluyentes = (d: PaqueteModo) => !(d.precio_abierto && d.cobro_por_noche)
const msgModo = {
  path: ['cobro_por_noche'],
  message: 'Un paquete no puede ser de precio abierto y por noche a la vez',
}

export const paqueteCreateSchema = paqueteBase.refine(precioSegunModo, msgPrecio).refine(modosExcluyentes, msgModo)
export const paqueteUpdateSchema = paqueteBase
  .partial()
  .refine(precioSegunModo, msgPrecio)
  .refine(modosExcluyentes, msgModo)

// ---------- Facturas ----------
// monto, comision_monto y monto_neto NO se aceptan del cliente: se recalculan
// en el servidor. precio_base solo se toma en cuenta si el paquete es de precio
// abierto; en un paquete de precio fijo la ruta lo descarta y usa el del
// paquete. El descuento y la comisión se clampan al recalcular.
export const facturaSchema = z
  .object({
    cliente_id: z.coerce.number().int().positive('El cliente es requerido'),
    paquete_id: z.coerce.number().int().positive('El paquete es requerido'),
    fecha_facturacion: fechaISO.optional(),
    // Opcional: en un paquete de precio abierto el cobro es único y la ruta la
    // fuerza a null. La ruta también la exige cuando el paquete sí tiene ciclo.
    fecha_proximo_pago: fechaISO.nullish(),
    precio_base: z.coerce.number().min(0, 'El precio no puede ser negativo').max(DEC_MAX).optional(),
    // Solo se usan cuando el paquete se cobra por noche; en el resto la ruta las
    // descarta y las guarda como NULL.
    noches: z.coerce.number().int().positive('Las noches deben ser mayor a 0').nullish(),
    precio_noche: z.coerce.number().min(0, 'La tarifa no puede ser negativa').max(DEC_MAX).nullish(),
    descuento_monto: z.coerce.number().min(0, 'El descuento no puede ser negativo').max(DEC_MAX).default(0),
    origen: z.string().trim().max(100).nullish(),
    comision_tipo: z.enum(['porcentaje', 'monto']).default('porcentaje'),
    comision_valor: z.coerce.number().min(0, 'La comisión no puede ser negativa').max(DEC_MAX).default(0),
  })
  .refine(
    (d) =>
      !d.fecha_facturacion ||
      !d.fecha_proximo_pago ||
      Date.parse(d.fecha_proximo_pago) >= Date.parse(d.fecha_facturacion),
    { path: ['fecha_proximo_pago'], message: 'El próximo pago no puede ser anterior a la facturación' }
  )
  .refine((d) => d.comision_tipo !== 'porcentaje' || d.comision_valor <= 100, {
    path: ['comision_valor'],
    message: 'El porcentaje de comisión no puede superar 100',
  })

// ---------- Exportación de facturación ----------
// El período del reporte: un rango de fechas, un mes completo o todo lo
// facturado. Los campos que no corresponden al modo elegido se ignoran.
export const facturaExportQuerySchema = z
  .object({
    modo: z.enum(['rango', 'mes', 'total']).default('total'),
    desde: fechaISO.optional(),
    hasta: fechaISO.optional(),
    mes: z.string().regex(/^\d{4}-(0[1-9]|1[0-2])$/, 'Mes inválido: use el formato AAAA-MM').optional(),
  })
  .refine((d) => d.modo !== 'rango' || (!!d.desde && !!d.hasta), {
    path: ['desde'],
    message: 'Indique la fecha inicial y la final del rango',
  })
  .refine((d) => d.modo !== 'mes' || !!d.mes, { path: ['mes'], message: 'Indique el mes a exportar' })
  .refine(
    (d) => d.modo !== 'rango' || !d.desde || !d.hasta || Date.parse(d.hasta) >= Date.parse(d.desde),
    { path: ['hasta'], message: 'La fecha final no puede ser anterior a la inicial' }
  )

export type FacturaExportQuery = z.infer<typeof facturaExportQuerySchema>

// ---------- Auditoría ----------
export const auditoriaQuerySchema = z.object({
  tabla: z.enum(['clientes', 'paquetes', 'categorias', 'facturas', 'usuarios']).optional(),
  accion: z.enum(['create', 'update', 'delete']).optional(),
  registro_id: z.coerce.number().int().positive().optional(),
  usuario_id: z.coerce.number().int().positive().optional(),
  desde: fechaISO.optional(),
  hasta: fechaISO.optional(),
  pagina: z.coerce.number().int().positive().default(1),
  por_pagina: z.coerce.number().int().positive().max(200).default(50),
})
export type AuditoriaQuery = z.infer<typeof auditoriaQuerySchema>
