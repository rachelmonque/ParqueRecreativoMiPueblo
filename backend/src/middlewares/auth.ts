import { Request, Response, NextFunction } from 'express'
import jwt from 'jsonwebtoken'
import { env } from '../config/env'
import { auditContext } from '../lib/auditContext'

export interface AuthRequest extends Request {
  usuarioId?: number
  usuarioEmail?: string
  usuarioRol?: string
}

export function authMiddleware(req: AuthRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Token requerido' })
    return
  }

  const token = authHeader.split(' ')[1]

  try {
  const payload = jwt.verify(token, env.JWT_SECRET) as { id: number; email: string; rol: string }
    req.usuarioId = payload.id
    req.usuarioEmail = payload.email
    req.usuarioRol = payload.rol
    auditContext.run({ usuarioId: payload.id, usuarioEmail: payload.email }, next)
  } catch {
    res.status(401).json({ error: 'Token inválido o expirado' })
  }
}

// Exige un rol mínimo para continuar. Se usa después de authMiddleware, que
// ya puso req.usuarioRol a partir del JWT. Ver PoC1 (Falta de Autorización):
// antes de esto, cualquier token válido —sin importar el rol de la cuenta—
// podía ejecutar operaciones irreversibles como borrar un cliente.
export function requireRole(rolMinimo: string) {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (req.usuarioRol !== rolMinimo) {
      res.status(403).json({ error: 'No tiene permisos para esta acción' })
      return
    }
    next()
  }
}
