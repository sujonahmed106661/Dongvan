import asyncio
import logging
import re
import base64
import hashlib
import hmac as hmac_module
import struct
import time
import json
import os
import urllib.parse
import html as html_module
import numpy as np

import requests as req_lib
import cv2
from datetime import datetime

from telegram import Update, ReplyKeyboardMarkup, KeyboardButton, InlineKeyboardButton, InlineKeyboardMarkup, ChatMember
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes, CallbackQueryHandler
from telegram.error import TelegramError

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# ===== CONFIG =====
BOT_TOKEN       = "8863498956:AAE3CwqBBQLnYPjdEU99l5MCyCaNJ40YWRc"
ADMIN_IDS       = [8502686983]
DONGVAN_API_KEY = "ChXbDXJGgQMYFwqYfRANwLc7i"

# DongVan API URLs
OAUTH2_URL              = "https://api.dongvanfb.net/api/getOauth2"
GET_CODE_OAUTH2_URL     = "https://tools.dongvanfb.net/api/get_code_oauth2"
GET_MESSAGES_OAUTH2_URL = "https://tools.dongvanfb.net/api/get_messages_oauth2"
GRAPH_MESSAGES_URL      = "https://tools.dongvanfb.net/api/graph_messages"

# ===== Data Storage =====
DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "totp_data.json")

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {
        "otp_log": [], "totp_keys": {}, "key_counter": 0,
        "channels": ["@NeroxaOfficial", "@NeroxaMethod"],
        "users": {},
        "force_join_enabled": True
    }

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)

totp_data = load_data()

# Ensure keys exist in old data files
totp_data.setdefault("channels", ["@NeroxaOfficial", "@NeroxaMethod"])
totp_data.setdefault("users", {})
totp_data.setdefault("force_join_enabled", True)
save_data(totp_data)

# ===== Mail Box Sessions =====
mail_sessions = {}  # chat_id -> {email, password, refresh_token, client_id}

# ===== SERVICE KEYWORDS =====
SERVICE_KEYWORDS = {
    "FACEBOOK": ["security@facebookmail.com", "facebook", "fb"],
    "INSTAGRAM": ["instagram", "mail@instagram.com"],
    "TWITTER": ["twitter", "x.com", "notify@twitter.com"],
    "GOOGLE": ["google", "gmail", "youtube", "no-reply@google.com"],
    "APPLE": ["apple", "icloud", "no-reply@apple.com"],
    "TIKTOK": ["tiktok", "douyin"],
    "AMAZON": ["amazon", "shipment-tracking@amazon.com"],
    "SHOPEE": ["shopee"],
    "TELEGRAM": ["telegram"],
    "KAKAOTALK": ["kakao"],
    "LAZADA": ["lazada"],
    "WECHAT": ["wechat", "weixin"],
    "OUTLOOK": ["outlook", "microsoft", "hotmail", "no-reply@microsoft.com"],
    "LINKEDIN": ["linkedin"],
    "NETFLIX": ["netflix"],
    "DISCORD": ["discord"],
    "SNAPCHAT": ["snapchat"],
    "GARENA": ["garena"],
    "COINBASE": ["coinbase"],
    "BINANCE": ["binance"],
}
SERVICE_LIST = list(SERVICE_KEYWORDS.keys())

# ==============================================================
# ==================  FORCE JOIN  ==============================
# ==============================================================

async def check_membership(bot, user_id: int, channel: str) -> bool:
    try:
        member = await bot.get_chat_member(chat_id=channel, user_id=user_id)
        return member.status in [
            ChatMember.MEMBER, ChatMember.ADMINISTRATOR, ChatMember.OWNER
        ]
    except TelegramError:
        return False

async def get_unjoined_channels(bot, user_id: int) -> list:
    if not totp_data.get("force_join_enabled", True):
        return []
    channels = totp_data.get("channels", [])
    unjoined = []
    for ch in channels:
        if not await check_membership(bot, user_id, ch):
            unjoined.append(ch)
    return unjoined

def get_join_keyboard(unjoined_channels: list):
    buttons = []
    for ch in unjoined_channels:
        name = ch.lstrip("@")
        url = f"https://t.me/{name}" if ch.startswith("@") else ch
        buttons.append([InlineKeyboardButton(f"➕ Join {ch}", url=url)])
    buttons.append([InlineKeyboardButton("✅ Done — Check Again", callback_data="check_join")])
    return InlineKeyboardMarkup(buttons)

async def force_join_check(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Returns True if user passed join check, False if blocked."""
    user_id = update.effective_user.id
    if user_id in ADMIN_IDS:
        return True
    unjoined = await get_unjoined_channels(context.bot, user_id)
    if unjoined:
        ch_list = "\n".join(f"• {ch}" for ch in unjoined)
        await update.effective_message.reply_text(
            "⛔ *বট ব্যবহার করতে হলে আগে এই চ্যানেলগুলোতে Join করুন:*\n\n"
            f"{ch_list}\n\n"
            "Join করার পর ✅ Done বাটনে চাপুন।",
            reply_markup=get_join_keyboard(unjoined),
            parse_mode="Markdown"
        )
        return False
    return True

# ==============================================================
# ==================  TOTP FUNCTIONS  ==========================
# ==============================================================

def base32_decode(secret):
    padding = 8 - (len(secret) % 8)
    if padding != 8:
        secret += '=' * padding
    return base64.b32decode(secret.upper())

def generate_totp(secret_key, time_step=30, digits=6):
    try:
        key_bytes = base32_decode(secret_key)
        counter = int(time.time() / time_step)
        counter_bytes = struct.pack('>Q', counter)
        h = hmac_module.new(key_bytes, counter_bytes, hashlib.sha1).digest()
        offset = h[-1] & 0x0f
        truncated = struct.unpack('>I', h[offset:offset+4])[0] & 0x7fffffff
        return str(truncated % (10 ** digits)).zfill(digits)
    except Exception:
        return None

def get_current_totp(secret_key):
    code = generate_totp(secret_key)
    remaining = 30 - (int(time.time()) % 30)
    return code, remaining, 30

def get_next_totp(secret_key):
    time_step = 30
    counter = int(time.time() / time_step) + 1
    try:
        key_bytes = base32_decode(secret_key)
        counter_bytes = struct.pack('>Q', counter)
        h = hmac_module.new(key_bytes, counter_bytes, hashlib.sha1).digest()
        offset = h[-1] & 0x0f
        truncated = struct.unpack('>I', h[offset:offset+4])[0] & 0x7fffffff
        return str(truncated % (10 ** 6)).zfill(6)
    except Exception:
        return None

def get_next_key_name():
    totp_data['key_counter'] = totp_data.get('key_counter', 0) + 1
    save_data(totp_data)
    return f"Key_{totp_data['key_counter']}"

def detect_platform(text):
    text_lower = text.lower()
    platform_map = {
        "facebook": "Facebook", "fb": "Facebook", "meta": "Facebook",
        "google": "Google", "gmail": "Google", "youtube": "Google",
        "instagram": "Instagram", "ig": "Instagram",
        "twitter": "Twitter/X", "x": "Twitter/X",
        "github": "GitHub", "git": "GitHub",
        "microsoft": "Microsoft", "outlook": "Microsoft",
        "apple": "Apple", "icloud": "Apple",
        "whatsapp": "WhatsApp", "telegram": "Telegram",
        "discord": "Discord", "amazon": "Amazon",
    }
    for key, value in platform_map.items():
        if key in text_lower:
            return value
    return None

def extract_secret_from_qr(image_bytes):
    try:
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return None, "Could not decode image"
        detector = cv2.QRCodeDetector()
        data_str, _, _ = detector.detectAndDecode(img)
        if not data_str:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            data_str, _, _ = detector.detectAndDecode(gray)
        if not data_str:
            return None, "No QR code found"
        if 'otpauth://' in data_str:
            parsed = urllib.parse.urlparse(data_str)
            params = urllib.parse.parse_qs(parsed.query)
            secret = params.get('secret', [None])[0]
            issuer = params.get('issuer', ['Unknown'])[0]
            label = parsed.path.lstrip('/')
            if secret:
                return {'secret': secret, 'issuer': issuer, 'label': label}, None
        clean = data_str.upper().replace(' ', '')
        if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' for c in clean) and len(clean) >= 16:
            return {'secret': clean, 'issuer': 'QR Code', 'label': 'Direct Secret'}, None
        return None, "Unknown QR format"
    except Exception as e:
        return None, f"Error: {str(e)}"

def generate_timer_bar(remaining, total=30):
    filled = int((remaining / total) * 10)
    empty = 10 - filled
    return "🟢" * filled + "⚪" * empty

def format_code_message(key_name, code, remaining):
    bar = generate_timer_bar(remaining)
    next_code = get_next_totp(totp_data['totp_keys'][key_name]['secret'])
    return (
        f"🔑 *{key_name}*\n\n"
        f"📱 *Current:* `{code}`\n"
        f"⏳ *Next:* `{next_code}`\n\n"
        f"⏱ {bar} `{remaining}s`\n\n"
        f"_Tap code to copy_"
    )

def get_refresh_inline(key_name):
    return InlineKeyboardMarkup([[InlineKeyboardButton("🔄 Refresh", callback_data=f"ref_{key_name}")]])

# ==============================================================
# ==================  MAIL BOX FUNCTIONS  ======================
# ==============================================================

def determine_service(subject="", sender_name="", sender_address=""):
    text = f"{subject} {sender_name} {sender_address}".lower()
    for service, keywords in SERVICE_KEYWORDS.items():
        if any(kw.lower() in text for kw in keywords):
            return service
    return "UNKNOWN"

def extract_codes_from_messages(messages_data):
    found = []
    if not messages_data or not messages_data.get("status") or not messages_data.get("messages"):
        return found
    for msg in messages_data["messages"]:
        subject = msg.get("subject", "") or ""
        body = msg.get("message", "") or ""
        sender_name = ""
        sender_address = ""
        from_field = msg.get("from")
        if from_field and isinstance(from_field, list) and len(from_field) > 0:
            sender_name = from_field[0].get("name", "") or ""
            sender_address = from_field[0].get("address", "") or ""
        code = msg.get("code", "") or ""
        if not code:
            patterns = [
                r'(\d{4,8})\s+is your',
                r'[Cc]ode[:\s]+(\d{4,8})',
                r'[Cc]onfirmation code[:\s]*(\d{4,8})',
                r'[Vv]erification code[:\s]*(\d{4,8})',
                r'OTP[:\s]*(\d{4,8})',
                r'mã xác nhận[:\s]*(\d{4,8})',
                r'is\s+(\d{4,8})\s',
                r'security code[:\s]*(\d{4,8})',
            ]
            combined = subject + " " + body[:2000]
            for pattern in patterns:
                match = re.search(pattern, combined)
                if match:
                    code = match.group(1)
                    break
        if code:
            service = determine_service(subject, sender_name, sender_address)
            found.append({
                "code": code, "service": service,
                "sender": sender_name, "address": sender_address,
                "subject": subject, "date": msg.get("date", "") or "",
                "uid": msg.get("uid", "") or "",
            })
    return found

def parse_mail_input(user_input):
    parts = user_input.strip().split("|")
    result = {"email": None, "password": None, "refresh_token": None, "client_id": None, "has_oauth2": False}
    if len(parts) >= 2:
        result["email"] = parts[0].strip()
        result["password"] = parts[1].strip()
    if len(parts) >= 4:
        result["refresh_token"] = parts[2].strip()
        result["client_id"] = parts[3].strip()
        result["has_oauth2"] = True
    return result

def get_oauth2(email, password):
    try:
        resp = req_lib.post(OAUTH2_URL, json={"email": email, "password": password, "apikey": DONGVAN_API_KEY}, timeout=30)
        data = resp.json()
        if data.get("status") and "oauth2" in data:
            parts = data["oauth2"].split("|")
            if len(parts) >= 2:
                return {"refresh_token": parts[0], "client_id": parts[1]}
        return None
    except Exception as e:
        logger.error(f"OAuth2 error: {e}")
        return None

def get_messages_oauth2(email, refresh_token, client_id):
    try:
        resp = req_lib.post(GET_MESSAGES_OAUTH2_URL, json={
            "email": email, "refresh_token": refresh_token,
            "client_id": client_id, "list_mail": "all"
        }, timeout=30)
        return resp.json()
    except Exception as e:
        logger.error(f"get_messages error: {e}")
        return None

def get_code_oauth2(email, refresh_token, client_id, code_type="all"):
    try:
        resp = req_lib.post(GET_CODE_OAUTH2_URL, json={
            "email": email, "refresh_token": refresh_token,
            "client_id": client_id, "type": code_type
        }, timeout=30)
        return resp.json()
    except Exception as e:
        logger.error(f"get_code error: {e}")
        return None

def get_messages_graph(email, refresh_token, client_id):
    try:
        resp = req_lib.post(GRAPH_MESSAGES_URL, json={
            "email": email, "refresh_token": refresh_token,
            "client_id": client_id, "list_mail": "all"
        }, timeout=30)
        return resp.json()
    except Exception as e:
        logger.error(f"graph_messages error: {e}")
        return None

def process_full_mailbox(session):
    email = session["email"]
    rt = session["refresh_token"]
    cid = session["client_id"]
    msgs = get_messages_oauth2(email, rt, cid)
    if msgs and msgs.get("status") and msgs.get("messages"):
        return extract_codes_from_messages(msgs)
    msgs = get_messages_graph(email, rt, cid)
    if msgs and msgs.get("status") and msgs.get("messages"):
        return extract_codes_from_messages(msgs)
    return []

def build_mailbox_display(messages, filter_service=None):
    if filter_service:
        filtered = [m for m in messages if m["service"] == filter_service.upper()]
        title = f"📁 Filter: {filter_service.upper()}"
    else:
        filtered = messages
        title = "📁 Mailbox"
    if not filtered:
        return f"{title}\n━━━━━━━━━━━━━━━\n❌ No messages found."
    output = f"{title}\n━━━━━━━━━━━━━━━\n📊 Total: {len(filtered)} message(s)\n━━━━━━━━━━━━━━━\n\n"
    for i, m in enumerate(filtered[:15], 1):
        code_display = f"<b>{html_module.escape(m['code'])}</b>" if m['code'] else "No code"
        output += f"<b>#{i}</b> [{m['service']}] {code_display}\n"
        output += f"└─ 📝 {html_module.escape(m['subject'][:60])}\n"
        output += f"└─ 👤 {html_module.escape(m['sender'][:40])}\n"
        if m.get('date'):
            output += f"└─ 🕐 {str(m['date'])[:19]}\n"
        output += "\n"
    if len(filtered) > 15:
        output += f"... and {len(filtered) - 15} more\n\n"
    output += "━━━━━━━━━━━━━━━\n📋 <b>CODES:</b>\n"
    for m in filtered:
        if m['code']:
            output += f"<code>{m['service']} → {html_module.escape(m['code'])}</code>\n"
    return output

def build_codes_display(messages):
    if not messages:
        return "❌ No codes found."
    by_service = {}
    for m in messages:
        svc = m["service"]
        by_service.setdefault(svc, []).append(m)
    output = "━━━━━━━━━━━━━━━\n📬 <b>CODES FOUND</b>\n━━━━━━━━━━━━━━━\n\n"
    for svc, msgs in by_service.items():
        output += f"<b>{svc}</b>\n"
        for m in msgs:
            output += f"├─ <code>{html_module.escape(m['code'])}</code>\n"
            output += f"└─ {html_module.escape(m['subject'][:60])}\n"
        output += "\n"
    output += "━━━━━━━━━━━━━━━\n📋 <b>COPY:</b>\n"
    for svc, msgs in by_service.items():
        for m in msgs:
            output += f"<code>{svc} → {html_module.escape(m['code'])}</code>\n"
    return output

# ==============================================================
# ====================  KEYBOARDS  =============================
# ==============================================================

def get_main_keyboard(user_id=None):
    rows = [[KeyboardButton("🔑 2FA Manager"), KeyboardButton("📬 Mail Box")]]
    if user_id and user_id in ADMIN_IDS:
        rows.append([KeyboardButton("⚙️ Admin Panel")])
    return ReplyKeyboardMarkup(rows, resize_keyboard=True)

def get_2fa_keyboard():
    keyboard = [
        [KeyboardButton("📥 Capture OTP")],
        [KeyboardButton("📋 View OTPs"), KeyboardButton("📊 Stats")],
        [KeyboardButton("🔑 All Keys"), KeyboardButton("🔢 Get Code")],
        [KeyboardButton("➕ Add Key"), KeyboardButton("🔄 Change Key")],
        [KeyboardButton("❌ Delete Key"), KeyboardButton("🗑 Clear All")],
        [KeyboardButton("❓ Help"), KeyboardButton("🏠 Main Menu")],
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)

def get_mailbox_keyboard():
    keyboard = [
        [KeyboardButton("📧 Set Mail"), KeyboardButton("📬 Get Code"), KeyboardButton("🔄 Refresh")],
        [KeyboardButton("📁 Read Mailbox"), KeyboardButton("🔍 Filter"), KeyboardButton("✏️ Change Mail")],
        [KeyboardButton("ℹ️ Help"), KeyboardButton("🏠 Main Menu")],
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)

def get_admin_keyboard():
    fj = "🟢 Force Join ON" if totp_data.get("force_join_enabled", True) else "🔴 Force Join OFF"
    keyboard = [
        [KeyboardButton("📢 Broadcast")],
        [KeyboardButton("➕ Add Channel"), KeyboardButton("➖ Remove Channel")],
        [KeyboardButton("📋 Channel List"), KeyboardButton(fj)],
        [KeyboardButton("👥 Total Users"), KeyboardButton("📊 Bot Stats")],
        [KeyboardButton("🏠 Main Menu")],
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)

def get_cancel_keyboard():
    return ReplyKeyboardMarkup([[KeyboardButton("❌ Cancel")]], resize_keyboard=True, one_time_keyboard=True)

def get_keys_keyboard():
    keys = list(totp_data.get('totp_keys', {}).keys())
    keyboard = []
    row = []
    for name in keys:
        row.append(KeyboardButton(f"🗝 {name}"))
        if len(row) == 2:
            keyboard.append(row)
            row = []
    if row:
        keyboard.append(row)
    keyboard.append([KeyboardButton("❌ Cancel")])
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True, one_time_keyboard=True)

def get_service_inline_keyboard():
    buttons = []
    row = []
    for i, svc in enumerate(SERVICE_LIST[:18]):
        row.append(InlineKeyboardButton(svc, callback_data=f"filter_{svc}"))
        if len(row) == 3:
            buttons.append(row)
            row = []
    if row:
        buttons.append(row)
    return InlineKeyboardMarkup(buttons)

# ==============================================================
# ====================  AUTO UPDATE  ===========================
# ==============================================================

async def auto_update_codes(app):
    while True:
        await asyncio.sleep(1)
        bot_data = app.bot_data
        live_msgs = bot_data.get('live_messages', {})
        if not live_msgs:
            continue
        now = time.time()
        to_delete = []
        for msg_id, info in list(live_msgs.items()):
            if now >= info['expires_at']:
                try:
                    key_name = info['key_name']
                    keys = totp_data.get('totp_keys', {})
                    if key_name in keys:
                        secret = keys[key_name]['secret']
                        code, remaining, _ = get_current_totp(secret)
                        msg = format_code_message(key_name, code, remaining)
                        try:
                            await app.bot.edit_message_text(
                                chat_id=info['chat_id'],
                                message_id=msg_id,
                                text=msg,
                                reply_markup=get_refresh_inline(key_name),
                                parse_mode="Markdown"
                            )
                            bot_data['live_messages'][msg_id]['expires_at'] = time.time() + remaining
                        except Exception:
                            pass
                    else:
                        to_delete.append(msg_id)
                except Exception:
                    to_delete.append(msg_id)
        for msg_id in to_delete:
            bot_data['live_messages'].pop(msg_id, None)

async def post_init(app):
    asyncio.create_task(auto_update_codes(app))

# ==============================================================
# ====================  HELPERS  ===============================
# ==============================================================

def _register_live(context, msg_id, chat_id, key_name, remaining):
    if 'live_messages' not in context.bot_data:
        context.bot_data['live_messages'] = {}
    context.bot_data['live_messages'][msg_id] = {
        'chat_id': chat_id, 'key_name': key_name, 'expires_at': time.time() + remaining
    }

def track_user(update: Update):
    user = update.effective_user
    if user:
        totp_data.setdefault("users", {})[str(user.id)] = {
            "id": user.id,
            "name": user.full_name,
            "username": user.username or "",
            "joined": totp_data["users"].get(str(user.id), {}).get("joined",
                      datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        }
        save_data(totp_data)

# ==============================================================
# ====================  HANDLERS  ==============================
# ==============================================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        if not await force_join_check(update, context):
            return
    track_user(update)
    context.user_data.clear()
    await update.message.reply_text(
        "🤖 *Combined Bot*\n\n"
        "দুইটা ফিচার নিচের বাটন থেকে বেছে নিন:\n\n"
        "🔑 *2FA Manager* — TOTP/OTP keys manage করুন\n"
        "📬 *Mail Box* — Outlook mail থেকে OTP code বের করুন",
        reply_markup=get_main_keyboard(user_id),
        parse_mode="Markdown"
    )

async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        if not await force_join_check(update, context):
            return
    track_user(update)

    mode = context.user_data.get('mode', 'main')
    if mode != '2fa':
        return await update.message.reply_text("🔑 2FA Manager এ যান QR code পাঠাতে।",
                                               reply_markup=get_main_keyboard(user_id))

    photo = update.message.photo[-1]
    file = await context.bot.get_file(photo.file_id)
    image_bytes = await file.download_as_bytearray()

    result, error = extract_secret_from_qr(image_bytes)
    if error:
        return await update.message.reply_text(f"❌ {error}", reply_markup=get_2fa_keyboard())

    if result:
        secret = result['secret']
        code, remaining, _ = get_current_totp(secret)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if context.user_data.get('update_key'):
            key_name = context.user_data['update_key']
            totp_data['totp_keys'][key_name]['secret'] = secret
            totp_data['totp_keys'][key_name]['updated'] = timestamp
            save_data(totp_data)
            context.user_data.pop('update_key', None)
            msg = format_code_message(key_name, code, remaining)
            sent = await update.message.reply_text(f"✅ *Updated!*\n\n{msg}",
                                                   reply_markup=get_refresh_inline(key_name), parse_mode="Markdown")
            _register_live(context, sent.message_id, sent.chat_id, key_name, remaining)
            return

        key_name = get_next_key_name()
        totp_data.setdefault('totp_keys', {})[key_name] = {
            'secret': secret, 'issuer': result.get('issuer', 'QR Code'),
            'added': timestamp, 'label': key_name, 'source': result.get('label', 'QR')
        }
        save_data(totp_data)
        msg = format_code_message(key_name, code, remaining)
        sent = await update.message.reply_text(f"✅ *Auto-Saved!*\n\n{msg}",
                                               reply_markup=get_refresh_inline(key_name), parse_mode="Markdown")
        _register_live(context, sent.message_id, sent.chat_id, key_name, remaining)

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text.strip()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    username = update.effective_user.username or f"User_{user_id}"

    # Force join check (skip for admins)
    if user_id not in ADMIN_IDS:
        if not await force_join_check(update, context):
            return

    track_user(update)

    mode = context.user_data.get('mode', 'main')

    # ── Global buttons ──
    if text == "🏠 Main Menu":
        context.user_data.clear()
        await update.message.reply_text("🏠 *Main Menu*\n\nফিচার বেছে নিন:",
                                        reply_markup=get_main_keyboard(user_id), parse_mode="Markdown")
        return

    if text == "❌ Cancel":
        context.user_data.pop('state', None)
        context.user_data.pop('update_key', None)
        context.user_data.pop('broadcast_pending', None)
        context.user_data.pop('add_channel_pending', None)
        context.user_data.pop('remove_channel_pending', None)
        if mode == '2fa':
            kb = get_2fa_keyboard()
        elif mode == 'mail':
            kb = get_mailbox_keyboard()
        elif mode == 'admin':
            kb = get_admin_keyboard()
        else:
            kb = get_main_keyboard(user_id)
        await update.message.reply_text("✅ Cancelled.", reply_markup=kb)
        return

    # ── Mode Select ──
    if text == "🔑 2FA Manager":
        context.user_data['mode'] = '2fa'
        await update.message.reply_text(
            "🔑 *2FA Manager*\n\n"
            "✅ QR code পাঠালে auto-save হবে\n"
            "✅ OTP code পাঠালে auto-detect হবে\n"
            "✅ Live timer সহ code দেখাবে\n\n"
            "নিচের বাটন ব্যবহার করুন 👇",
            reply_markup=get_2fa_keyboard(), parse_mode="Markdown"
        )
        return

    if text == "📬 Mail Box":
        context.user_data['mode'] = 'mail'
        await update.message.reply_text(
            "📬 *Mail Box*\n\n"
            "Outlook/Hotmail থেকে verification code বের করুন।\n\n"
            "📧 *Set Mail* বাটন দিয়ে শুরু করুন।\n"
            "Format: `email|password` অথবা `email|password|refresh_token|client_id`",
            reply_markup=get_mailbox_keyboard(), parse_mode="Markdown"
        )
        return

    if text == "⚙️ Admin Panel":
        if user_id not in ADMIN_IDS:
            return await update.message.reply_text("⛔ Unauthorized.", reply_markup=get_main_keyboard(user_id))
        context.user_data['mode'] = 'admin'
        channels = totp_data.get("channels", [])
        ch_list = "\n".join(f"• {ch}" for ch in channels) or "কোনো channel নেই"
        users_count = len(totp_data.get("users", {}))
        fj_status = "🟢 ON" if totp_data.get("force_join_enabled", True) else "🔴 OFF"
        await update.message.reply_text(
            f"⚙️ *Admin Panel*\n\n"
            f"👥 Total Users: *{users_count}*\n"
            f"📢 Force Join: *{fj_status}*\n"
            f"📋 Channels:\n{ch_list}",
            reply_markup=get_admin_keyboard(), parse_mode="Markdown"
        )
        return

    # ══════════════════════════════════════
    # ──────── Admin Panel ─────────────────
    # ══════════════════════════════════════
    if mode == 'admin':
        if user_id not in ADMIN_IDS:
            await update.message.reply_text("⛔ Unauthorized.")
            return

        # State: waiting broadcast message
        if context.user_data.get('broadcast_pending'):
            context.user_data.pop('broadcast_pending')
            users = totp_data.get("users", {})
            if not users:
                await update.message.reply_text("❌ কোনো user নেই।", reply_markup=get_admin_keyboard())
                return
            sent_count = 0
            fail_count = 0
            broadcast_text = text
            status_msg = await update.message.reply_text(f"📢 Broadcasting to {len(users)} users...")
            for uid_str, uinfo in users.items():
                try:
                    await context.bot.send_message(
                        chat_id=int(uid_str),
                        text=broadcast_text
                    )
                    sent_count += 1
                except TelegramError:
                    fail_count += 1
                await asyncio.sleep(0.05)
            await status_msg.edit_text(
                f"✅ *Broadcast Done!*\n\n"
                f"✅ Sent: {sent_count}\n"
                f"❌ Failed: {fail_count}",
                parse_mode="Markdown"
            )
            await update.message.reply_text("✅ Broadcast complete.", reply_markup=get_admin_keyboard())
            return

        # State: waiting add channel
        if context.user_data.get('add_channel_pending'):
            context.user_data.pop('add_channel_pending')
            ch = text.strip()
            if ch.startswith("https://t.me/"):
                ch = "@" + ch[len("https://t.me/"):].rstrip("/")
            elif not ch.startswith("@"):
                ch = "@" + ch
            channels = totp_data.setdefault("channels", [])
            if ch in channels:
                await update.message.reply_text(f"⚠️ `{ch}` already আছে।",
                                                reply_markup=get_admin_keyboard(), parse_mode="Markdown")
            else:
                channels.append(ch)
                save_data(totp_data)
                await update.message.reply_text(f"✅ Channel added: `{ch}`",
                                                reply_markup=get_admin_keyboard(), parse_mode="Markdown")
            return

        # State: waiting remove channel
        if context.user_data.get('remove_channel_pending'):
            context.user_data.pop('remove_channel_pending')
            ch = text.strip()
            if not ch.startswith("@"):
                ch = "@" + ch
            channels = totp_data.get("channels", [])
            if ch in channels:
                channels.remove(ch)
                save_data(totp_data)
                await update.message.reply_text(f"🗑 Channel removed: `{ch}`",
                                                reply_markup=get_admin_keyboard(), parse_mode="Markdown")
            else:
                await update.message.reply_text(f"❌ `{ch}` পাওয়া যায়নি।",
                                                reply_markup=get_admin_keyboard(), parse_mode="Markdown")
            return

        if text == "📢 Broadcast":
            context.user_data['broadcast_pending'] = True
            users_count = len(totp_data.get("users", {}))
            await update.message.reply_text(
                f"📢 *Broadcast Message*\n\n"
                f"👥 {users_count} জন user কে পাঠানো হবে।\n\n"
                f"এখন message লিখুন:",
                reply_markup=get_cancel_keyboard(), parse_mode="Markdown"
            )
            return

        if text == "➕ Add Channel":
            context.user_data['add_channel_pending'] = True
            await update.message.reply_text(
                "➕ *Add Channel*\n\n"
                "Channel username লিখুন:\n"
                "উদাহরণ: `@NeroxaOfficial`",
                reply_markup=get_cancel_keyboard(), parse_mode="Markdown"
            )
            return

        if text == "➖ Remove Channel":
            channels = totp_data.get("channels", [])
            if not channels:
                await update.message.reply_text("❌ কোনো channel নেই।", reply_markup=get_admin_keyboard())
                return
            context.user_data['remove_channel_pending'] = True
            ch_list = "\n".join(f"• `{ch}`" for ch in channels)
            await update.message.reply_text(
                f"➖ *Remove Channel*\n\n"
                f"Current channels:\n{ch_list}\n\n"
                f"Remove করতে channel username লিখুন:",
                reply_markup=get_cancel_keyboard(), parse_mode="Markdown"
            )
            return

        if text == "📋 Channel List":
            channels = totp_data.get("channels", [])
            fj = "🟢 ON" if totp_data.get("force_join_enabled", True) else "🔴 OFF"
            if channels:
                ch_list = "\n".join(f"• `{ch}`" for ch in channels)
            else:
                ch_list = "কোনো channel নেই"
            await update.message.reply_text(
                f"📋 *Force Join Channels*\n\n"
                f"Status: {fj}\n\n{ch_list}",
                reply_markup=get_admin_keyboard(), parse_mode="Markdown"
            )
            return

        if text in ("🟢 Force Join ON", "🔴 Force Join OFF"):
            current = totp_data.get("force_join_enabled", True)
            totp_data["force_join_enabled"] = not current
            save_data(totp_data)
            new_status = "🟢 ON" if totp_data["force_join_enabled"] else "🔴 OFF"
            await update.message.reply_text(
                f"✅ Force Join এখন *{new_status}*",
                reply_markup=get_admin_keyboard(), parse_mode="Markdown"
            )
            return

        if text == "👥 Total Users":
            users = totp_data.get("users", {})
            count = len(users)
            if count == 0:
                await update.message.reply_text("👥 কোনো user নেই।", reply_markup=get_admin_keyboard())
                return
            lines = [f"👥 <b>Total Users: {count}</b>\n"]
            for uid_str, info in list(users.items())[-20:]:
                uname = f"@{html_module.escape(info['username'])}" if info.get('username') else "—"
                safe_name = html_module.escape(str(info.get('name', '?')))
                lines.append(f"• {safe_name} ({uname}) <code>{uid_str}</code>")
            await update.message.reply_text("\n".join(lines)[:4096],
                                            reply_markup=get_admin_keyboard(), parse_mode="HTML")
            return

        if text == "📊 Bot Stats":
            users_count = len(totp_data.get("users", {}))
            otp_count = len(totp_data.get('otp_log', []))
            key_count = len(totp_data.get('totp_keys', {}))
            ch_count = len(totp_data.get("channels", []))
            fj = "🟢 ON" if totp_data.get("force_join_enabled", True) else "🔴 OFF"
            await update.message.reply_text(
                f"📊 *Bot Stats*\n\n"
                f"👥 Users: {users_count}\n"
                f"🔑 TOTP Keys: {key_count}\n"
                f"📥 OTP Logs: {otp_count}\n"
                f"📢 Channels: {ch_count}\n"
                f"🔒 Force Join: {fj}",
                reply_markup=get_admin_keyboard(), parse_mode="Markdown"
            )
            return

        await update.message.reply_text("❓ বাটন ব্যবহার করুন:", reply_markup=get_admin_keyboard())
        return

    # ══════════════════════════════════════
    # ──────── 2FA Manager ────────────────
    # ══════════════════════════════════════
    if mode == '2fa':
        state = context.user_data.get('state')

        if state in ("waiting_update_select", "waiting_delete_select"):
            selected = text[2:] if text.startswith("🗝 ") else text
            keys = totp_data.get('totp_keys', {})
            if selected not in keys:
                await update.message.reply_text("❌ Not found.", reply_markup=get_keys_keyboard())
                return
            if state == "waiting_update_select":
                context.user_data['update_key'] = selected
                context.user_data.pop('state', None)
                await update.message.reply_text(
                    f"🔄 `{selected}` এর জন্য নতুন QR বা secret key পাঠান:",
                    reply_markup=get_cancel_keyboard(), parse_mode="Markdown"
                )
            elif state == "waiting_delete_select":
                del totp_data['totp_keys'][selected]
                save_data(totp_data)
                context.user_data.clear()
                context.user_data['mode'] = '2fa'
                await update.message.reply_text(f"🗑 Deleted: `{selected}`",
                                                reply_markup=get_2fa_keyboard(), parse_mode="Markdown")
            return

        if text == "📥 Capture OTP":
            await update.message.reply_text("📥 OTP, QR code, অথবা secret key পাঠান:",
                                            reply_markup=get_cancel_keyboard())
            return

        if text == "📋 View OTPs":
            otp_log = totp_data.get('otp_log', [])
            if not otp_log:
                return await update.message.reply_text("📭 No OTPs.", reply_markup=get_2fa_keyboard())
            msg = "📋 *OTPs*\n\n"
            for entry in otp_log[-30:]:
                p = entry.get('platform', '?')
                msg += f"🔑 `{entry['otp']}` — {p} — {entry['timestamp'][:16]}\n"
            await update.message.reply_text(msg[:4000], reply_markup=get_2fa_keyboard(), parse_mode="Markdown")
            return

        if text == "📊 Stats":
            otp_count = len(totp_data.get('otp_log', []))
            key_count = len(totp_data.get('totp_keys', {}))
            platforms = {}
            for entry in totp_data.get('otp_log', []):
                p = entry.get('platform', 'Unknown')
                platforms[p] = platforms.get(p, 0) + 1
            ps = "\n".join(f"• {p}: {c}" for p, c in sorted(platforms.items(), key=lambda x: -x[1]))
            await update.message.reply_text(
                f"📊 *Stats*\nOTPs: {otp_count}\nKeys: {key_count}\n\n{ps or 'No data'}",
                reply_markup=get_2fa_keyboard(), parse_mode="Markdown"
            )
            return

        if text == "🔑 All Keys":
            keys = totp_data.get('totp_keys', {})
            if not keys:
                return await update.message.reply_text("No keys.", reply_markup=get_2fa_keyboard())
            msg = "🔑 *All Keys*\n\n"
            for name, info in keys.items():
                code, remaining, _ = get_current_totp(info['secret'])
                bar = generate_timer_bar(remaining)
                msg += f"🔑 `{name}`: `{code}` {bar} {remaining}s\n"
            await update.message.reply_text(msg[:4000], reply_markup=get_2fa_keyboard(), parse_mode="Markdown")
            return

        if text == "🔢 Get Code":
            keys = totp_data.get('totp_keys', {})
            if not keys:
                return await update.message.reply_text("No keys.", reply_markup=get_2fa_keyboard())
            await update.message.reply_text("Key বেছে নিন:", reply_markup=get_keys_keyboard())
            return

        if text.startswith("🗝 "):
            key_name = text[2:]
            keys = totp_data.get('totp_keys', {})
            if key_name in keys:
                secret = keys[key_name]['secret']
                code, remaining, _ = get_current_totp(secret)
                msg = format_code_message(key_name, code, remaining)
                sent = await update.message.reply_text(msg, reply_markup=get_refresh_inline(key_name),
                                                       parse_mode="Markdown")
                _register_live(context, sent.message_id, sent.chat_id, key_name, remaining)
            return

        if text == "➕ Add Key":
            await update.message.reply_text(
                "➕ *Add Key*\n\n"
                "🔹 QR code image পাঠান → Auto-Save\n"
                "🔹 Secret key টাইপ করে পাঠান\n\n"
                "কোনো বাটন প্রেস করতে হবে না!",
                reply_markup=get_cancel_keyboard(), parse_mode="Markdown"
            )
            return

        if text == "🔄 Change Key":
            keys = totp_data.get('totp_keys', {})
            if not keys:
                return await update.message.reply_text("No keys.", reply_markup=get_2fa_keyboard())
            context.user_data['state'] = "waiting_update_select"
            await update.message.reply_text("Key বেছে নিন (change করতে):", reply_markup=get_keys_keyboard())
            return

        if text == "❌ Delete Key":
            keys = totp_data.get('totp_keys', {})
            if not keys:
                return await update.message.reply_text("No keys.", reply_markup=get_2fa_keyboard())
            context.user_data['state'] = "waiting_delete_select"
            await update.message.reply_text("Delete করতে key বেছে নিন:", reply_markup=get_keys_keyboard())
            return

        if text == "🗑 Clear All":
            kb = InlineKeyboardMarkup([[
                InlineKeyboardButton("✅ Yes", callback_data="2fa_clr_yes"),
                InlineKeyboardButton("❌ No", callback_data="2fa_clr_no")
            ]])
            await update.message.reply_text("⚠️ সব OTP log এবং key delete করবেন?", reply_markup=kb)
            return

        if text == "❓ Help":
            await update.message.reply_text(
                "🤖 *2FA Manager Help*\n\n"
                "📤 QR পাঠালে auto-save — code + timer দেখাবে\n"
                "🔐 Secret key পাঠালেও auto-save\n"
                "📥 OTP code auto-detect হবে\n"
                "⏱ Live timer — 30s পর code auto-change\n"
                "🔄 Refresh বাটন দিয়ে manually refresh",
                reply_markup=get_2fa_keyboard(), parse_mode="Markdown"
            )
            return

        # OTP detection
        otp_match = re.search(r'\b(\d{6})\b', text)
        if otp_match:
            otp = otp_match.group(1)
            platform = detect_platform(text) or "Unknown"
            entry = {'otp': otp, 'platform': platform, 'timestamp': timestamp, 'username': username}
            totp_data.setdefault('otp_log', []).append(entry)
            save_data(totp_data)
            await update.message.reply_text(f"✅ *{platform}*: `{otp}`",
                                            reply_markup=get_2fa_keyboard(), parse_mode="Markdown")
            return

        # Secret key auto-save
        clean = text.upper().replace(' ', '')
        if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' for c in clean) and len(clean) >= 16:
            code, remaining, _ = get_current_totp(clean)
            if code:
                if context.user_data.get('update_key'):
                    key_name = context.user_data['update_key']
                    totp_data['totp_keys'][key_name]['secret'] = clean
                    totp_data['totp_keys'][key_name]['updated'] = timestamp
                    save_data(totp_data)
                    context.user_data.pop('update_key', None)
                    msg = format_code_message(key_name, code, remaining)
                    sent = await update.message.reply_text(
                        f"✅ *Updated!*\n\n{msg}",
                        reply_markup=get_refresh_inline(key_name), parse_mode="Markdown"
                    )
                    _register_live(context, sent.message_id, sent.chat_id, key_name, remaining)
                    return

                key_name = get_next_key_name()
                totp_data.setdefault('totp_keys', {})[key_name] = {
                    'secret': clean, 'issuer': 'Manual', 'added': timestamp, 'label': key_name
                }
                save_data(totp_data)
                msg = format_code_message(key_name, code, remaining)
                sent = await update.message.reply_text(
                    f"✅ *Auto-Saved!*\n\n{msg}",
                    reply_markup=get_refresh_inline(key_name), parse_mode="Markdown"
                )
                _register_live(context, sent.message_id, sent.chat_id, key_name, remaining)
                return

        await update.message.reply_text("❓ বাটন ব্যবহার করুন:", reply_markup=get_2fa_keyboard())
        return

    # ══════════════════════════════════════
    # ──────── Mail Box ───────────────────
    # ══════════════════════════════════════
    if mode == 'mail':
        session = mail_sessions.get(update.effective_chat.id)

        if text == "📧 Set Mail":
            await update.message.reply_text(
                "📧 *Set Mail*\n\n"
                "আপনার account data পাঠান:\n\n"
                "`email|password|refresh_token|client_id`\n\n"
                "অথবা শুধু:\n`email|password`\n\n"
                "OAuth2 না থাকলে auto-fetch করব।",
                reply_markup=get_cancel_keyboard(), parse_mode="Markdown"
            )
            return

        if text == "✏️ Change Mail":
            mail_sessions.pop(update.effective_chat.id, None)
            await update.message.reply_text(
                "✏️ *Change Mail*\n\nSession clear হয়েছে। নতুন data পাঠান:\n"
                "`email|password|refresh_token|client_id`",
                reply_markup=get_cancel_keyboard(), parse_mode="Markdown"
            )
            return

        if text == "📬 Get Code":
            if not session:
                return await update.message.reply_text("❌ Mail set করুন আগে।", reply_markup=get_mailbox_keyboard())
            wait_msg = await update.message.reply_text(
                f"🔄 Fetching codes for <code>{html_module.escape(session['email'])}</code>...", parse_mode="HTML")
            code_data = get_code_oauth2(session["email"], session["refresh_token"], session["client_id"])
            all_messages = []
            if code_data and code_data.get("status") and code_data.get("code"):
                svc = determine_service(code_data.get("content", ""), "", "")
                all_messages.append({"code": code_data["code"], "service": svc,
                                     "subject": code_data.get("content", ""), "sender": "", "date": ""})
            msgs_data = get_messages_oauth2(session["email"], session["refresh_token"], session["client_id"])
            if msgs_data and msgs_data.get("status"):
                existing = {m["code"] for m in all_messages}
                for c in extract_codes_from_messages(msgs_data):
                    if c["code"] not in existing:
                        all_messages.append(c)
            display = build_codes_display(all_messages)
            try:
                await wait_msg.delete()
            except Exception:
                pass
            await update.message.reply_text(display[:4096], parse_mode="HTML", reply_markup=get_mailbox_keyboard())
            return

        if text == "🔄 Refresh":
            if not session:
                return await update.message.reply_text("❌ Mail set করুন আগে।", reply_markup=get_mailbox_keyboard())
            wait_msg = await update.message.reply_text("🔄 Refreshing...")
            messages = process_full_mailbox(session)
            display = build_mailbox_display(messages)
            try:
                await wait_msg.delete()
            except Exception:
                pass
            await update.message.reply_text(
                f"📧 <code>{html_module.escape(session['email'])}</code>\n\n{display}"[:4096],
                parse_mode="HTML", reply_markup=get_mailbox_keyboard()
            )
            return

        if text == "📁 Read Mailbox":
            if not session:
                return await update.message.reply_text("❌ Mail set করুন আগে।", reply_markup=get_mailbox_keyboard())
            wait_msg = await update.message.reply_text("📁 Loading mailbox...")
            messages = process_full_mailbox(session)
            display = build_mailbox_display(messages)
            try:
                await wait_msg.delete()
            except Exception:
                pass
            await update.message.reply_text(
                f"📧 <code>{html_module.escape(session['email'])}</code>\n\n{display}"[:4096],
                parse_mode="HTML", reply_markup=get_mailbox_keyboard()
            )
            return

        if text == "🔍 Filter":
            if not session:
                return await update.message.reply_text("❌ Mail set করুন আগে।", reply_markup=get_mailbox_keyboard())
            await update.message.reply_text(
                f"🔍 <b>Filter by Service</b>\n📧 <code>{html_module.escape(session['email'])}</code>\n\nService বেছে নিন:",
                parse_mode="HTML", reply_markup=get_service_inline_keyboard()
            )
            return

        if text == "ℹ️ Help":
            await update.message.reply_text(
                "📬 <b>Mail Box Help</b>\n\n"
                "📧 <b>Set Mail</b> — email|password দিয়ে শুরু\n"
                "📬 <b>Get Code</b> — সর্বশেষ verification code\n"
                "🔄 <b>Refresh</b> — mailbox refresh করুন\n"
                "📁 <b>Read Mailbox</b> — সব mail দেখুন\n"
                "🔍 <b>Filter</b> — service অনুযায়ী filter\n"
                "✏️ <b>Change Mail</b> — নতুন account set করুন",
                parse_mode="HTML", reply_markup=get_mailbox_keyboard()
            )
            return

        # email|password input
        if "|" in text:
            parsed = parse_mail_input(text)
            if not parsed["email"]:
                await update.message.reply_text(
                    "❌ Invalid format.\n`email|password|refresh_token|client_id`",
                    reply_markup=get_mailbox_keyboard(), parse_mode="Markdown"
                )
                return
            wait_msg = await update.message.reply_text(
                f"🔄 Processing <code>{html_module.escape(parsed['email'])}</code>...", parse_mode="HTML")
            if not parsed["has_oauth2"]:
                oauth2 = get_oauth2(parsed["email"], parsed["password"])
                if not oauth2:
                    try:
                        await wait_msg.edit_text(
                            f"❌ OAuth2 failed for <code>{html_module.escape(parsed['email'])}</code>",
                            parse_mode="HTML")
                    except Exception:
                        pass
                    return
                parsed["refresh_token"] = oauth2["refresh_token"]
                parsed["client_id"] = oauth2["client_id"]
            mail_sessions[update.effective_chat.id] = {
                "email": parsed["email"], "password": parsed["password"],
                "refresh_token": parsed["refresh_token"], "client_id": parsed["client_id"]
            }
            messages = process_full_mailbox(mail_sessions[update.effective_chat.id])
            display = build_mailbox_display(messages)
            cid_val = parsed.get("client_id") or ""
            cid_preview = cid_val[:20] + "..." if len(cid_val) > 20 else cid_val
            try:
                await wait_msg.edit_text(
                    f"✅ <b>Mail Set!</b>\n📧 <code>{html_module.escape(parsed['email'])}</code>\n"
                    f"🆔 <code>{html_module.escape(cid_preview)}</code>\n\n{display}"[:4096],
                    parse_mode="HTML"
                )
            except Exception:
                pass
            await update.message.reply_text("✅ Mail সেট হয়েছে!", reply_markup=get_mailbox_keyboard())
            return

        await update.message.reply_text("❓ বাটন ব্যবহার করুন:", reply_markup=get_mailbox_keyboard())
        return

    # Main menu default
    await update.message.reply_text("👇 ফিচার বেছে নিন:", reply_markup=get_main_keyboard(user_id))

async def handle_callbacks(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    chat_id = query.message.chat_id
    user_id = update.effective_user.id

    # Force join re-check
    if data == "check_join":
        unjoined = await get_unjoined_channels(context.bot, user_id)
        if unjoined:
            ch_list = "\n".join(f"• {ch}" for ch in unjoined)
            await query.edit_message_text(
                f"⛔ *এখনও Join করেননি:*\n\n{ch_list}\n\nJoin করে আবার চেষ্টা করুন।",
                reply_markup=get_join_keyboard(unjoined),
                parse_mode="Markdown"
            )
        else:
            await query.edit_message_text("✅ সব channel এ join করেছেন! এখন /start দিন।")
        return

    # 2FA clear
    if data == "2fa_clr_yes":
        totp_data['otp_log'] = []
        totp_data['totp_keys'] = {}
        totp_data['key_counter'] = 0
        save_data(totp_data)
        await query.edit_message_text("🗑 All cleared.")
        return

    if data == "2fa_clr_no":
        await query.edit_message_text("✅ Cancelled.")
        return

    # TOTP refresh
    if data.startswith("ref_"):
        key_name = data[4:]
        keys = totp_data.get('totp_keys', {})
        if key_name not in keys:
            await query.edit_message_text("❌ Key deleted.")
            return
        code, remaining, _ = get_current_totp(keys[key_name]['secret'])
        msg = format_code_message(key_name, code, remaining)
        try:
            await query.edit_message_text(msg, reply_markup=get_refresh_inline(key_name), parse_mode="Markdown")
            _register_live(context, query.message.message_id, chat_id, key_name, remaining)
        except Exception:
            pass
        return

    # Service filter
    if data.startswith("filter_"):
        service = data[7:]
        session = mail_sessions.get(chat_id)
        if not session:
            await query.edit_message_text("❌ Mail set করুন।")
            return
        messages = process_full_mailbox(session)
        display = build_mailbox_display(messages, filter_service=service)
        await query.edit_message_text(
            f"📧 <code>{html_module.escape(session['email'])}</code>\n\n{display}"[:4096],
            parse_mode="HTML"
        )
        return

# ==============================================================
# ==========================  MAIN  ============================
# ==============================================================

def main():
    if not BOT_TOKEN:
        raise ValueError("BOT_TOKEN environment variable is not set!")

    app = Application.builder().token(BOT_TOKEN).post_init(post_init).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.PHOTO, handle_photo))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.add_handler(CallbackQueryHandler(handle_callbacks))

    logger.info("Combined Bot started!")
    app.run_polling()

if __name__ == "__main__":
    main()
