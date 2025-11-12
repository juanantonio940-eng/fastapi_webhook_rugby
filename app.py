import os
import imaplib
import email as email_lib
import email.header
from typing import List, Optional
import logging
from datetime import datetime, timedelta
import re
from email.utils import parsedate_to_datetime
import secrets

import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

# Configura logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

IMAP_HOST = "imap.mail.me.com"
IMAP_PORT = 993

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("Falta la variable de entorno DATABASE_URL")

# ===== CONFIGURACIÓN DE SEGURIDAD =====
WEBHOOK_USERNAME = os.getenv("WEBHOOK_USERNAME", "admin")
WEBHOOK_PASSWORD = os.getenv("WEBHOOK_PASSWORD", "cambiar_password_123")

app = FastAPI()
security = HTTPBasic()


def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    """
    Verifica las credenciales del usuario usando comparación segura.
    """
    correct_username = secrets.compare_digest(credentials.username, WEBHOOK_USERNAME)
    correct_password = secrets.compare_digest(credentials.password, WEBHOOK_PASSWORD)
    
    if not (correct_username and correct_password):
        logger.warning(f"❌ Intento de acceso no autorizado: {credentials.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    logger.info(f"✅ Acceso autorizado para usuario: {credentials.username}")
    return credentials.username


# ------- MODELOS -------

class WebhookInput(BaseModel):
    email: str


class Message(BaseModel):
    from_: str
    subject: str
    date: str
    to: str
    otp_code: Optional[str] = None
    activation_url: Optional[str] = None
    email_type: str
    folder: str


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


def is_within_last_minutes(date_str: str, minutes: int = 10) -> bool:
    """
    Verifica si el email es de los últimos N minutos.
    """
    if not date_str:
        return False
    
    try:
        email_date = parsedate_to_datetime(date_str)
        now = datetime.now(email_date.tzinfo) if email_date.tzinfo else datetime.now()
        time_diff = now - email_date
        is_recent = time_diff <= timedelta(minutes=minutes)
        
        logger.info(f"⏰ Email de hace {time_diff.total_seconds()/60:.1f} minutos - {'✅ Reciente' if is_recent else '❌ Antiguo'}")
        
        return is_recent
    except Exception as e:
        logger.warning(f"⚠️ Error parseando fecha '{date_str}': {e}")
        return True


def extract_otp_code(text: str) -> Optional[str]:
    """
    Extrae el código OTP de 6 dígitos del texto del email.
    """
    if not text:
        return None
    
    patterns = [
        r'código[:\s]+(\d{6})',
        r'code[:\s]+(\d{6})',
        r'verification[:\s]+(\d{6})',
        r'\b(\d{6})\b',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            otp = match.group(1)
            logger.info(f"🔑 OTP encontrado: {otp}")
            return otp
    
    logger.warning("⚠️ No se encontró código OTP")
    return None


def extract_activation_url(text: str) -> Optional[str]:
    """
    Extrae la URL de activación del email.
    """
    if not text:
        return None
    
    logger.info("🔍 Buscando URL de activación...")
    
    patterns = [
        r'(https://rwc2027\.tmtickets\.co\.uk/Authentication/ActivateAccount/[^\s<>"\']+)',
        r'(https://[^\s<>"\']*tmtickets\.co\.uk[^\s<>"\']*)',
        r'(https://rwc2027\.rugbyworldcup\.com/[^\s<>"\']{20,})',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            url = max(matches, key=len)
            url = url.rstrip('.,;)\'"')
            url = url.replace('&amp;', '&')
            url = url.replace('&quot;', '"')
            url = url.replace('&#39;', "'")
            url = url.replace('&lt;', '<')
            url = url.replace('&gt;', '>')
            
            logger.info(f"🔗 URL de activación encontrada ({len(url)} chars): {url[:100]}...")
            return url
    
    logger.warning("⚠️ No se encontró URL de activación con patrones específicos")
    
    all_urls = re.findall(r'https://[^\s<>"\']+', text)
    if all_urls:
        long_urls = [url for url in all_urls if len(url) > 100]
        if long_urls:
            url = max(long_urls, key=len)
            url = url.rstrip('.,;)\'"')
            url = url.replace('&amp;', '&')
            logger.info(f"🔗 URL larga encontrada ({len(url)} chars): {url[:100]}...")
            return url
    
    logger.warning("⚠️ No se encontró ninguna URL de activación")
    return None


def extract_recipient_email(header_text: str) -> Optional[str]:
    """
    Extrae el email del destinatario desde los headers.
    """
    recipient = None
    
    for line in header_text.split('\n'):
        line_lower = line.lower()
        if line_lower.startswith('delivered-to:') or line_lower.startswith('to:') or line_lower.startswith('x-original-to:'):
            email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', line)
            if email_match:
                recipient = email_match.group(0).lower()
                logger.info(f"📬 Destinatario encontrado: {recipient}")
                return recipient
    
    return recipient


def search_in_folder(imap, folder_name: str, target_email: str, limit: int = 1, minutes: int = 10, max_emails_to_check: int = 30) -> List[Message]:
    """
    Busca mensajes en una carpeta específica de los últimos N minutos.
    Solo revisa los últimos max_emails_to_check correos para ser más rápido.
    """
    found_messages: List[Message] = []
    target_email_lower = target_email.lower().strip()
    
    try:
        status, count = imap.select(folder_name)
        if status != "OK":
            logger.warning(f"⚠️ No se pudo abrir la carpeta {folder_name}")
            return []
        
        logger.info(f"📁 Buscando en carpeta: {folder_name}")
        
        status, data = imap.search(None, "ALL")
        
        if status != "OK" or not data or not data[0]:
            logger.info(f"⚠️ No se encontraron mensajes en {folder_name}")
            return []

        all_ids = data[0].split()
        total_emails = len(all_ids)
        logger.info(f"📬 Total de mensajes en {folder_name}: {total_emails}")
        
        ids_to_check = all_ids[-max_emails_to_check:]
        logger.info(f"⚡ Revisando solo los últimos {len(ids_to_check)} correos (de {total_emails} totales)")
        
        emails_checked = 0
        
        for msg_id in reversed(ids_to_check):
            if len(found_messages) >= limit:
                break
            
            emails_checked += 1
            logger.info(f"📩 Procesando mensaje ID: {msg_id} ({emails_checked}/{len(ids_to_check)})")
            
            status, header_data = imap.fetch(msg_id, "(FLAGS BODY.PEEK[HEADER])")
            
            if status != "OK" or not header_data:
                logger.warning(f"⚠️ Error fetching headers del mensaje {msg_id}")
                continue
            
            flags_str = str(header_data)
            if '\\Seen' in flags_str:
                logger.info(f"⏭️ Saltando - mensaje ya leído")
                continue
            
            header_bytes = None
            for part in header_data:
                if isinstance(part, tuple) and len(part) >= 2:
                    header_bytes = part[1]
                    break
                elif isinstance(part, bytes):
                    header_bytes = part
                    break
            
            if not header_bytes:
                logger.warning(f"⚠️ No se pudieron extraer headers")
                continue
            
            try:
                header_text = header_bytes.decode('utf-8', errors='ignore')
                
                subject = ""
                from_header = ""
                date_header = ""
                
                for line in header_text.split('\n'):
                    if line.lower().startswith('subject:'):
                        subject = line.split(':', 1)[1].strip()
                        subject = decode_header_part(subject)
                    elif line.lower().startswith('from:'):
                        from_header = line.split(':', 1)[1].strip()
                        from_header = decode_header_part(from_header)
                    elif line.lower().startswith('date:'):
                        date_header = line.split(':', 1)[1].strip()
                
                if not is_within_last_minutes(date_header, minutes):
                    logger.info(f"⏭️ Saltando - email muy antiguo (más de {minutes} minutos)")
                    continue
                
                logger.info(f"📨 Subject: '{subject}'")
                logger.info(f"📨 From: '{from_header}'")
                
                email_type = None
                
                if "fifa id" in subject.lower():
                    email_type = "FIFA"
                    logger.info(f"🎯 ¡Encontrado mensaje de FIFA!")
                elif "noreplyrwc2027@rugbyworldcup.com" in from_header.lower():
                    subject_lower = subject.lower()
                    if ("activate" in subject_lower and "rugby world cup" in subject_lower) or \
                       "ticketing account" in subject_lower:
                        email_type = "RUGBY"
                        logger.info(f"🏉 ¡Encontrado mensaje de Rugby World Cup 2027!")
                
                if not email_type:
                    logger.info(f"⏭️ Saltando mensaje - no es de FIFA ni Rugby")
                    continue
                
                recipient_email = extract_recipient_email(header_text)
                
                if not recipient_email:
                    logger.warning(f"⚠️ No se pudo extraer el email destinatario")
                    continue
                
                logger.info(f"🔍 Comparando: '{recipient_email}' vs '{target_email_lower}'")
                
                if recipient_email.lower() != target_email_lower:
                    logger.info(f"⏭️ Saltando - destinatario no coincide")
                    continue
                
                logger.info(f"✅ Correo destinado a {target_email_lower} - procesando...")
                
            except Exception as e:
                logger.warning(f"⚠️ Error parseando headers: {e}")
                continue
            
            logger.info(f"📥 Obteniendo mensaje completo")
            status, msg_data = imap.fetch(msg_id, "(BODY[])")
            
            if status != "OK" or not msg_data:
                logger.warning(f"⚠️ Error fetching mensaje completo")
                continue

            raw_msg = None
            for part in msg_data:
                if isinstance(part, tuple) and len(part) >= 2:
                    if isinstance(part[1], (bytes, bytearray)):
                        raw_msg = part[1]
                        break
                elif isinstance(part, (bytes, bytearray)) and len(part) > 100:
                    raw_msg = part
                    break

            if not raw_msg:
                logger.error(f"❌ No se pudo extraer raw_msg")
                continue

            try:
                msg = email_lib.message_from_bytes(raw_msg)

                subject_full = decode_header_part(msg.get("Subject"))
                from_ = decode_header_part(msg.get("From"))
                to_ = decode_header_part(msg.get("To"))
                date_ = msg.get("Date") or ""
                
                logger.info(f"📧 Email parseado completo")

                body_text = ""
                body_html = ""
                
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        content_disposition = str(part.get("Content-Disposition", ""))
                        
                        if content_type == "text/plain" and "attachment" not in content_disposition:
                            payload = part.get_payload(decode=True)
                            if payload:
                                try:
                                    body_text = payload.decode(errors="ignore")
                                    logger.info(f"✅ Text/plain: {len(body_text)} chars")
                                except:
                                    pass
                        
                        elif content_type == "text/html" and "attachment" not in content_disposition:
                            payload = part.get_payload(decode=True)
                            if payload:
                                try:
                                    body_html = payload.decode(errors="ignore")
                                    logger.info(f"✅ Text/html: {len(body_html)} chars")
                                except:
                                    pass
                else:
                    content_type = msg.get_content_type()
                    payload = msg.get_payload(decode=True)
                    if payload:
                        try:
                            if content_type == "text/plain":
                                body_text = payload.decode(errors="ignore")
                            elif content_type == "text/html":
                                body_html = payload.decode(errors="ignore")
                        except:
                            pass

                if not body_text and not body_html:
                    logger.warning(f"⚠️ No se pudo extraer body")
                    continue

                otp_code = None
                activation_url = None
                
                if email_type == "FIFA":
                    otp_code = extract_otp_code(body_text or body_html)
                    if otp_code:
                        logger.info(f"🎉 Código OTP: {otp_code}")
                
                elif email_type == "RUGBY":
                    if body_html:
                        activation_url = extract_activation_url(body_html)
                    if not activation_url and body_text:
                        activation_url = extract_activation_url(body_text)
                    
                    if activation_url:
                        logger.info(f"🎉 URL extraída correctamente")
                    else:
                        logger.warning(f"⚠️ No se encontró URL")
                
                if otp_code or activation_url:
                    try:
                        status, response = imap.store(msg_id, '+FLAGS', '\\Seen')
                        logger.info(f"📝 Store status: {status}")
                        
                        imap.expunge()
                        logger.info(f"✅ Mensaje {msg_id} marcado como LEÍDO y persistido")
                    except Exception as e:
                        logger.warning(f"⚠️ Error marcando como leído: {e}")
                    
                    found_messages.append(
                        Message(
                            from_=from_,
                            subject=subject_full or subject,
                            date=date_,
                            to=to_ or recipient_email,
                            otp_code=otp_code,
                            activation_url=activation_url,
                            email_type=email_type,
                            folder=folder_name,
                        )
                    )
                    logger.info(f"✅ Mensaje {email_type} agregado desde {folder_name}")
                
            except Exception as e:
                logger.error(f"❌ Error parseando: {e}")
                continue
        
        logger.info(f"📊 Revisados {emails_checked} correos en {folder_name}")
        
    except Exception as e:
        logger.error(f"❌ Error en carpeta {folder_name}: {e}")
    
    return found_messages


def fetch_last_messages(icloud_user: str, icloud_pass: str, target_email: str, limit: int = 1, minutes: int = 10, max_emails_to_check: int = 30) -> List[Message]:
    """
    Conecta con iCloud IMAP y devuelve los últimos N mensajes NO LEÍDOS de los últimos X minutos.
    Busca en INBOX y en Junk/Spam.
    """
    imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
    try:
        imap.login(icloud_user, icloud_pass)
        logger.info(f"✅ Login exitoso para {icloud_user}")
    except imaplib.IMAP4.error as e:
        raise Exception(f"Error autenticando en iCloud: {e}")

    logger.info(f"🎯 Buscando correos para: {target_email}")
    logger.info(f"⏰ Solo emails de los últimos {minutes} minutos")
    logger.info(f"⚡ Máximo {max_emails_to_check} correos por carpeta")
    
    all_messages: List[Message] = []
    
    folders_to_check = ["INBOX", "Junk"]
    
    for folder in folders_to_check:
        logger.info(f"\n{'='*60}")
        logger.info(f"🔍 Revisando carpeta: {folder}")
        logger.info(f"{'='*60}")
        
        messages = search_in_folder(imap, folder, target_email, limit, minutes, max_emails_to_check)
        all_messages.extend(messages)
        
        if len(all_messages) >= limit:
            logger.info(f"✅ Límite alcanzado ({limit} mensajes)")
            break
    
    try:
        imap.close()
        logger.info("✅ Carpeta cerrada correctamente")
    except Exception as e:
        logger.warning(f"⚠️ Error cerrando carpeta: {e}")
    
    imap.logout()
    logger.info(f"📊 Total procesados: {len(all_messages)}")
    return all_messages[:limit]


# ------- RUTAS CON AUTENTICACIÓN -------

@app.get("/")
def home(username: str = Depends(verify_credentials)):
    """Endpoint protegido con autenticación"""
    return {
        "status": "ok", 
        "mensaje": "FastAPI + Supabase + iCloud listo", 
        "user": username,
        "authenticated": True
    }


@app.post("/webhook", response_model=WebhookResponse)
def handle_webhook(payload: WebhookInput, username: str = Depends(verify_credentials)):
    """Webhook protegido con autenticación HTTP Basic"""
    logger.info(f"🎯 Webhook recibido para: {payload.email} (por usuario: {username})")
    
    account = get_account(payload.email)
    if not account:
        logger.error(f"❌ Cuenta no encontrada")
        raise HTTPException(status_code=404, detail="Cuenta no encontrada")

    icloud_user = account["icloud_user"]
    icloud_pass = account["icloud_app_password"]
    logger.info(f"🔑 Credenciales encontradas")

    try:
        messages = fetch_last_messages(
            icloud_user, 
            icloud_pass, 
            payload.email, 
            limit=1, 
            minutes=10, 
            max_emails_to_check=30
        )
        logger.info(f"✅ Mensajes obtenidos: {len(messages)}")
    except Exception as e:
        logger.error(f"❌ Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    return WebhookResponse(email=payload.email, messages=messages)
