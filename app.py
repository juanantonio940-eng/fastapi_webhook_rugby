import os
import imaplib
import email as email_lib
import email.header
from typing import List, Optional
import logging
from datetime import datetime
import re

import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Configura logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

IMAP_HOST = "imap.mail.me.com"
IMAP_PORT = 993

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("Falta la variable de entorno DATABASE_URL")

app = FastAPI()


# ------- MODELOS -------

class WebhookInput(BaseModel):
    email: str  # correo que te llega por el webhook (MAIL_MADRE o ALIAS)


class Message(BaseModel):
    from_: str
    subject: str
    date: str
    otp_code: Optional[str]  # Código OTP de 6 dígitos
    to: str  # A quién fue enviado el correo


class WebhookResponse(BaseModel):
    email: str
    messages: List[Message]


# ------- HELPERS DB -------

def get_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def get_account(email_in: str) -> Optional[dict]:
    """
    Busca en icloud_accounts una fila donde MAIL_MADRE = email
    o ALIAS = email. Devuelve usuario y password de iCloud.
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    "MAIL_MADRE" AS icloud_user,
                    "PASSWORD"   AS icloud_app_password
                FROM "icloud_accounts"
                WHERE "MAIL_MADRE" = %s
                   OR "ALIAS"      = %s
                LIMIT 1
                """,
                (email_in, email_in),
            )
            row = cur.fetchone()
            return row
    finally:
        conn.close()


# ------- HELPERS IMAP (iCloud) -------

def decode_header_part(value: Optional[str]) -> str:
    """
    Decodifica cualquier encabezado MIME (Subject, From, etc.)
    """
    if not value:
        return ""
    try:
        decoded_parts = email_lib.header.decode_header(value)
        decoded_str = ""
        for part, enc in decoded_parts:
            if isinstance(part, bytes):
                decoded_str += part.decode(enc or "utf-8", errors="ignore")
            elif isinstance(part, str):
                decoded_str += part
            else:
                decoded_str += str(part)
        return decoded_str
    except Exception as e:
        logger.warning(f"⚠️ Error decodificando header: {e}")
        return str(value) if value else ""


def extract_otp_code(text: str) -> Optional[str]:
    """
    Extrae el código OTP de 6 dígitos del texto del email.
    Busca patrones como: 123456, o "código: 123456", etc.
    """
    if not text:
        return None
    
    # Buscar 6 dígitos consecutivos
    patterns = [
        r'código[:\s]+(\d{6})',  # código: 123456
        r'code[:\s]+(\d{6})',     # code: 123456
        r'verification[:\s]+(\d{6})',  # verification: 123456
        r'\b(\d{6})\b',           # cualquier número de 6 dígitos aislado
    ]
    
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            otp = match.group(1)
            logger.info(f"🔑 OTP encontrado: {otp}")
            return otp
    
    logger.warning("⚠️ No se encontró código OTP en el texto")
    return None


def extract_recipient_email(header_text: str) -> Optional[str]:
    """
    Extrae el email del destinatario desde los headers.
    Busca en To:, Delivered-To:, X-Original-To:, etc.
    """
    recipient = None
    
    for line in header_text.split('\n'):
        line_lower = line.lower()
        if line_lower.startswith('delivered-to:') or line_lower.startswith('to:') or line_lower.startswith('x-original-to:'):
            # Extraer el email de la línea
            email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', line)
            if email_match:
                recipient = email_match.group(0).lower()
                logger.info(f"📬 Destinatario encontrado: {recipient}")
                return recipient
    
    return recipient


def fetch_last_messages(icloud_user: str, icloud_pass: str, target_email: str, limit: int = 1) -> List[Message]:
    """
    Conecta con iCloud IMAP y devuelve los últimos N mensajes NO LEÍDOS del día actual con asunto que contiene "FIFA ID"
    y que fueron enviados específicamente al target_email.
    Marca los mensajes como leídos después de procesarlos.
    """
    imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
    try:
        imap.login(icloud_user, icloud_pass)
        logger.info(f"✅ Login exitoso para {icloud_user}")
    except imaplib.IMAP4.error as e:
        raise Exception(f"Error autenticando en iCloud: {e}")

    imap.select("INBOX")

    # Obtener fecha de hoy en formato IMAP: DD-Mon-YYYY (ej: 09-Nov-2025)
    today = datetime.now().strftime("%d-%b-%Y")
    logger.info(f"📅 Fecha de hoy: {today}")
    logger.info(f"🎯 Buscando correos para: {target_email}")
    
    # Buscar mensajes NO LEÍDOS desde hoy
    search_criteria = f'(UNSEEN SINCE {today})'
    logger.info(f"🔍 Buscando mensajes NO LEÍDOS del día de hoy: {search_criteria}")
    
    status, data = imap.search(None, search_criteria)
    logger.info(f"📧 Status de búsqueda: {status}")
    
    if status != "OK" or not data or not data[0]:
        logger.warning("⚠️ No se encontraron mensajes no leídos de hoy")
        imap.logout()
        return []

    unread_ids = data[0].split()
    logger.info(f"📬 Total de mensajes NO LEÍDOS de hoy: {len(unread_ids)}")
    
    # Procesar de atrás hacia adelante para encontrar los últimos emails de FIFA
    fifa_messages: List[Message] = []
    
    # Normalizar el email objetivo para comparación
    target_email_lower = target_email.lower().strip()
    
    # Invertir la lista para empezar por los más recientes
    for msg_id in reversed(unread_ids):
        if len(fifa_messages) >= limit:
            break
            
        logger.info(f"📩 Procesando mensaje ID: {msg_id}")
        
        # Primero obtener headers completos para verificar destinatario y asunto
        status, header_data = imap.fetch(msg_id, "(BODY.PEEK[HEADER])")
        
        if status != "OK" or not header_data:
            logger.warning(f"⚠️ Error fetching headers del mensaje {msg_id}")
            continue
        
        # Extraer headers
        header_bytes = None
        for part in header_data:
            if isinstance(part, tuple) and len(part) >= 2:
                header_bytes = part[1]
                break
            elif isinstance(part, bytes):
                header_bytes = part
                break
        
        if not header_bytes:
            logger.warning(f"⚠️ No se pudieron extraer headers del mensaje {msg_id}")
            continue
        
        # Parsear los headers
        try:
            header_text = header_bytes.decode('utf-8', errors='ignore')
            
            # Extraer Subject
            subject = ""
            for line in header_text.split('\n'):
                if line.lower().startswith('subject:'):
                    subject = line.split(':', 1)[1].strip()
                    subject = decode_header_part(subject)
                    break
            
            logger.info(f"📨 Subject extraído: '{subject}'")
            
            # Filtrar por asunto que contenga "FIFA ID" (case-insensitive)
            if not subject or "fifa id" not in subject.lower():
                logger.info(f"⏭️ Saltando mensaje - no contiene 'FIFA ID' en el asunto")
                continue
            
            logger.info(f"🎯 ¡Encontrado mensaje de FIFA!")
            
            # Extraer destinatario del email
            recipient_email = extract_recipient_email(header_text)
            
            if not recipient_email:
                logger.warning(f"⚠️ No se pudo extraer el email destinatario")
                continue
            
            logger.info(f"🔍 Comparando destinatario: '{recipient_email}' vs solicitado: '{target_email_lower}'")
            
            # Verificar que el correo fue enviado al email solicitado
            if recipient_email.lower() != target_email_lower:
                logger.info(f"⏭️ Saltando mensaje - destinatario '{recipient_email}' no coincide con '{target_email_lower}'")
                continue
            
            logger.info(f"✅ Correo destinado a {target_email_lower} - procesando...")
            
        except Exception as e:
            logger.warning(f"⚠️ Error parseando headers: {e}")
            continue
        
        # Ahora obtener el mensaje completo usando BODY[]
        logger.info(f"📥 Obteniendo mensaje completo con BODY[]")
        status, msg_data = imap.fetch(msg_id, "(BODY[])")
        
        if status != "OK" or not msg_data:
            logger.warning(f"⚠️ Error fetching mensaje completo {msg_id}")
            continue

        # Extraer raw_msg
        raw_msg = None
        
        for i, part in enumerate(msg_data):
            if isinstance(part, tuple):
                if len(part) >= 2:
                    if isinstance(part[1], (bytes, bytearray)):
                        raw_msg = part[1]
                        logger.info(f"✅ Raw message encontrado en tupla[1], tamaño: {len(raw_msg)} bytes")
                        break
            elif isinstance(part, (bytes, bytearray)):
                if len(part) > 100:  # Debe ser más grande que metadata
                    raw_msg = part
                    logger.info(f"✅ Raw message encontrado directamente, tamaño: {len(raw_msg)} bytes")
                    break

        if not raw_msg:
            logger.error(f"❌ No se pudo extraer raw_msg del mensaje {msg_id}")
            continue

        # Parsear el mensaje
        try:
            msg = email_lib.message_from_bytes(raw_msg)

            subject_full = decode_header_part(msg.get("Subject"))
            from_ = decode_header_part(msg.get("From"))
            to_ = decode_header_part(msg.get("To"))
            date_ = msg.get("Date") or ""
            
            logger.info(f"📧 Email parseado - Subject: '{subject_full}', From: '{from_}', To: '{to_}'")

            body = ""
            if msg.is_multipart():
                logger.info("📄 Mensaje es multipart")
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition", ""))
                    
                    if (
                        content_type == "text/plain"
                        and "attachment" not in content_disposition
                    ):
                        payload = part.get_payload(decode=True)
                        if payload:
                            try:
                                body = payload.decode(errors="ignore")
                                logger.info(f"✅ Body extraído (multipart), tamaño: {len(body)} chars")
                            except Exception as e:
                                body = str(payload)
                                logger.warning(f"⚠️ Error decodificando body: {e}")
                            break
            else:
                logger.info("📄 Mensaje es single-part")
                content_type = msg.get_content_type()
                
                if content_type == "text/plain":
                    payload = msg.get_payload(decode=True)
                    if payload:
                        try:
                            body = payload.decode(errors="ignore")
                            logger.info(f"✅ Body extraído (single-part), tamaño: {len(body)} chars")
                        except Exception as e:
                            body = str(payload)
                            logger.warning(f"⚠️ Error decodificando body: {e}")
                elif content_type == "text/html":
                    payload = msg.get_payload(decode=True)
                    if payload:
                        try:
                            body = payload.decode(errors="ignore")
                            logger.info(f"✅ Body HTML extraído, tamaño: {len(body)} chars")
                        except Exception as e:
                            body = str(payload)
                            logger.warning(f"⚠️ Error decodificando body HTML: {e}")

            if not body:
                logger.warning(f"⚠️ No se pudo extraer body del mensaje")
                body = str(msg.get_payload())

            # Extraer el código OTP del body
            otp_code = extract_otp_code(body)
            
            if otp_code:
                logger.info(f"🎉 Código OTP extraído exitosamente: {otp_code}")
                
                # Marcar el mensaje como leído
                try:
                    imap.store(msg_id, '+FLAGS', '\\Seen')
                    logger.info(f"✅ Mensaje {msg_id} marcado como LEÍDO")
                except Exception as e:
                    logger.warning(f"⚠️ Error marcando mensaje como leído: {e}")
            else:
                logger.warning(f"⚠️ No se encontró código OTP en el mensaje")
                logger.info(f"📝 Primeros 500 chars del body: {body[:500]}")

            fifa_messages.append(
                Message(
                    from_=from_,
                    subject=subject_full or subject,
                    date=date_,
                    otp_code=otp_code,
                    to=to_ or recipient_email,
                )
            )
            logger.info(f"✅ Mensaje FIFA agregado correctamente a la lista")
            
        except Exception as e:
            logger.error(f"❌ Error parseando mensaje: {e}")
            continue

    imap.logout()
    logger.info(f"📊 Total mensajes FIFA procesados: {len(fifa_messages)}")
    return fifa_messages


# ------- RUTAS -------

@app.get("/")
def home():
    return {"status": "ok", "mensaje": "FastAPI + Supabase + iCloud listo"}


@app.post("/webhook", response_model=WebhookResponse)
def handle_webhook(payload: WebhookInput):
    logger.info(f"🎯 Webhook recibido para email: {payload.email}")
    
    # 1) Buscar la cuenta en Supabase
    account = get_account(payload.email)
    if not account:
        logger.error(f"❌ Cuenta no encontrada para {payload.email}")
        raise HTTPException(
            status_code=404,
            detail="Cuenta no encontrada en icloud_accounts para ese email",
        )

    icloud_user = account["icloud_user"]
    icloud_pass = account["icloud_app_password"]
    logger.info(f"🔑 Credenciales encontradas para: {icloud_user}")

    # 2) Leer correos de iCloud
    try:
        # Pasar el email objetivo para filtrar
        messages = fetch_last_messages(icloud_user, icloud_pass, payload.email, limit=1)
        logger.info(f"✅ Mensajes obtenidos: {len(messages)}")
    except imaplib.IMAP4.error as e:
        logger.error(f"❌ Error IMAP: {e}")
        raise HTTPException(status_code=401, detail=f"Error autenticando en iCloud: {e}")
    except Exception as e:
        logger.error(f"❌ Error general: {e}")
        raise HTTPException(status_code=500, detail=f"Error leyendo correo: {e}")

    return WebhookResponse(email=payload.email, messages=messages)
