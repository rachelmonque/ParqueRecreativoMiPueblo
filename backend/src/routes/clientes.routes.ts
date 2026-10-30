import { Router } from 'express'
import rateLimit from 'express-rate-limit'
import prisma from '../lib/prisma'
import { authMiddleware, AuthRequest } from '../middlewares/auth'
import { validate } from '../middlewares/validate'
import { clienteCreateSchema, clienteUpdateSchema } from '../schemas/validation'
import { logger } from '../lib/logger'

const router = Router()
// Limita las lecturas individuales por id (por IP) para frenar la
// enumeración automatizada de :id (IDOR, ver PoC3): sin este límite, una
// cuenta válida puede recorrer secuencialmente toda la tabla de clientes
// y extraer su PII sin disparar ninguna alerta.
const lecturaIndividualLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiadas solicitudes. Intente de nuevo en un minuto.' },
})

// GET /api/clientes — protegido
router.get('/', authMiddleware, async (_req, res, next) => {
  try {
    const clientes = await prisma.clientes.findMany({
      orderBy: { nombre: 'asc' }
    })
    res.json(clientes)
  } catch (err) {
    next(err)
  }
})

// GET /api/clientes/proximos-a-vencer — protegido
// Devuelve clientes cuyo próximo pago vence en los próximos 7 días
router.get('/proximos-a-vencer', authMiddleware, async (_req, res, next) => {
  try {
    const hoy = new Date()
    const en7dias = new Date()
    en7dias.setDate(hoy.getDate() + 7)

    const facturas = await prisma.facturas.findMany({
      where: {
        fecha_proximo_pago: { gte: hoy, lte: en7dias }
      },
      include: { clientes: true, paquetes: true },
      orderBy: { fecha_proximo_pago: 'asc' }
    })
    res.json(facturas)
  } catch (err) {
    next(err)
  }
})

// GET /api/clientes/en-mora — protegido
// Devuelve clientes activos cuya factura más reciente ya venció
router.get('/en-mora', authMiddleware, async (_req, res, next) => {
  try {
    const hoy = new Date()

    const clientesActivos = await prisma.clientes.findMany({
      where: { estado: 'activo' },
      include: {
        facturas: {
          // Las facturas de pago único (sin próximo pago) quedan fuera: no
          // generan mora y, al ordenar DESC, Postgres pondría sus NULL primero
          // y tomaríamos una factura sin fecha como la más reciente.
          where: { fecha_proximo_pago: { not: null } },
          orderBy: { fecha_proximo_pago: 'desc' },
          take: 1,
          include: { paquetes: { select: { nombre: true } } },
        },
      },
    })

    const enMora = clientesActivos
      .filter((c) => c.facturas.length > 0 && c.facturas[0].fecha_proximo_pago! < hoy)
      .map((c) => {
        const ultimaFactura = c.facturas[0]
        const diasAtraso = Math.floor(
          (hoy.getTime() - ultimaFactura.fecha_proximo_pago!.getTime()) / (1000 * 60 * 60 * 24)
        )
        return {
          id: c.id,
          nombre: c.nombre,
          cedula: c.cedula,
          telefono: c.telefono,
          fecha_proximo_pago: ultimaFactura.fecha_proximo_pago,
          paquete_nombre: ultimaFactura.paquetes.nombre,
          dias_atraso: diasAtraso,
        }
      })
      .sort((a, b) => b.dias_atraso - a.dias_atraso)

    res.json(enMora)
  } catch (err) {
    next(err)
  }
})

// GET /api/clientes/:id — protegido
router.get('/:id', authMiddleware, lecturaIndividualLimiter, async (req, res, next) => {
  try {
    const cliente = await prisma.clientes.findUnique({
      where: { id: Number(req.params.id) },
      include: { facturas: { include: { paquetes: { include: { categorias: true } } }, orderBy: { fecha_facturacion: 'desc' } } }
    })
    if (!cliente) {
      res.status(404).json({ error: 'Cliente no encontrado' })
      return
    }
    res.json(cliente)
  } catch (err) {
    next(err)
  }
})

// POST /api/clientes — protegido
router.post('/', authMiddleware, validate(clienteCreateSchema), async (req: AuthRequest, res, next) => {
  try {
    const { fecha_inicio, ...resto } = req.body
    const cliente = await prisma.clientes.create({
      data: { ...resto, fecha_inicio: new Date(fecha_inicio) }
    })
    logger.info({ clienteId: cliente.id, usuarioEmail: req.usuarioEmail }, 'Cliente creado')
    res.status(201).json(cliente)
  } catch (err) {
    next(err)
  }
})

// PUT /api/clientes/:id — protegido
router.put('/:id', authMiddleware, validate(clienteUpdateSchema), async (req: AuthRequest, res, next) => {
  try {
    const { fecha_inicio, ...resto } = req.body
    const cliente = await prisma.clientes.update({
      where: { id: Number(req.params.id) },
      data: fecha_inicio ? { ...resto, fecha_inicio: new Date(fecha_inicio) } : resto
    })
    logger.info({ clienteId: cliente.id, usuarioEmail: req.usuarioEmail }, 'Cliente actualizado')
    res.json(cliente)
  } catch (err) {
    next(err)
  }
})

// DELETE /api/clientes/:id — protegido
router.delete('/:id', authMiddleware, async (req: AuthRequest, res, next) => {
  try {
    await prisma.clientes.delete({
      where: { id: Number(req.params.id) }
    })
    logger.info({ clienteId: Number(req.params.id), usuarioEmail: req.usuarioEmail }, 'Cliente eliminado')
    res.status(204).send()
  } catch (err) {
    next(err)
  }
})

export default router
