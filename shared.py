# shared.py
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, List
import subprocess
import json
import os
import hashlib
import uuid

# Optional pyttsx3 TTS (better control over voices). If unavailable, we fall back to macOS `say`.
try:
    import pyttsx3
    _HAS_PYTTSX3 = True
except Exception:
    pyttsx3 = None
    _HAS_PYTTSX3 = False

@dataclass
class Event:
    ts: str
    source: str   # "UI" or "DEVICE"
    button: str   # "BTN1".."BTN6"
    language: str # "en"|"hi"|"it"|"de"|"fr"|"es"
    text: str
    device_id: str = "unknown"  # track which device triggered event
    user_id: str = "default"    # track which user

# In-memory state (fine for MVP)
CONFIG: Dict[str, Dict] = {
    "BTN1": {"label": "Help",              "texts": {"en": "I need help",           "hi": "मुझे मदद चाहिए",           "it": "Ho bisogno di aiuto",          "de": "Ich brauche Hilfe",         "fr": "J'ai besoin d'aide",           "es": "Necesito ayuda"}},
    "BTN2": {"label": "Medicines please",  "texts": {"en": "Medicines please",     "hi": "कृपया दवाएं दें",           "it": "Medicinali per favore",        "de": "Medikamente bitte",         "fr": "Médicaments s'il vous plaît",  "es": "Medicinas por favor"}},
    "BTN3": {"label": "Water",             "texts": {"en": "I need water",          "hi": "मुझे पानी चाहिए",          "it": "Ho bisogno di acqua",          "de": "Ich brauche Wasser",        "fr": "J'ai besoin d'eau",            "es": "Necesito agua"}},
    "BTN4": {"label": "I need rest",       "texts": {"en": "I need rest",           "hi": "मुझे आराम चाहिए",           "it": "Ho bisogno di riposo",         "de": "Ich brauche Ruhe",          "fr": "J'ai besoin de repos",         "es": "Necesito descanso"}},
    "BTN5": {"label": "Come here",         "texts": {"en": "Please come here",     "hi": "कृपया यहाँ आइए",           "it": "Per favore vieni qui",         "de": "Bitte komm her",            "fr": "S'il vous plaît, venez ici",   "es": "Por favor ven aquí"}},
    "BTN6": {"label": "Emergency",         "texts": {"en": "Emergency!",            "hi": "आपातकाल!",                "it": "Emergenza!",                   "de": "Notfall!",                  "fr": "Urgence!",                     "es": "¡Emergencia!"}},
}

HISTORY: List[Event] = []

# File-based persistence
EVENTS_FILE = "events.json"

def _load_events_from_file() -> List[Event]:
    """Load events from persistent JSON file, filtering out entries older than 7 days."""
    if not os.path.exists(EVENTS_FILE):
        return []
    try:
        with open(EVENTS_FILE, "r") as f:
            data = json.load(f)
        events = []
        cutoff = datetime.now() - timedelta(days=7)
        for item in data:
            try:
                evt_ts = datetime.strptime(item["ts"], "%Y-%m-%d %H:%M:%S")
                if evt_ts >= cutoff:
                    events.append(Event(**item))
            except Exception:
                pass
        return events
    except Exception:
        return []

def _save_events_to_file(events: List[Event]):
    """Persist events list to JSON file."""
    try:
        with open(EVENTS_FILE, "w") as f:
            json.dump([asdict(e) for e in events], f, indent=2)
    except Exception:
        pass

# Load initial history from file on startup
HISTORY = _load_events_from_file()

def _cleanup_old_events():
    """Remove events older than 7 days from both HISTORY and file."""
    global HISTORY
    cutoff = datetime.now() - timedelta(days=7)
    HISTORY = [e for e in HISTORY if datetime.strptime(e.ts, "%Y-%m-%d %H:%M:%S") >= cutoff]
    _save_events_to_file(HISTORY)

# ========== USER AUTHENTICATION LAYER ==========
USERS_FILE = "users.json"

SECURITY_QUESTIONS = [
    "What is your mother's maiden name?",
    "What was the name of your first pet?",
    "In what city were you born?",
    "What is the name of the street you grew up on?",
    "What is your favorite book?",
    "What was the make of your first car?",
    "What is your favorite movie?",
    "What school did you attend for primary school?",
]

def _hash_password(password: str) -> str:
    """Hash password using SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()

def _load_users() -> Dict:
    """Load user database from JSON file."""
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def _save_users(users: Dict):
    """Save user database to JSON file."""
    try:
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)
    except Exception:
        pass

def user_signup(email: str, password: str, primary_account: bool = True, name: str = None, phone: str = None, security_question: str = None, security_answer: str = None) -> Dict:
    """Create a new user account. Returns {success, message, user_id}.

    Password policy: min 7 chars, at least one digit, one uppercase, one special char.
    """
    import re
    users = _load_users()

    # Validate email
    if "@" not in email or "." not in email:
        return {"success": False, "message": "Invalid email format"}

    # Check if email already exists
    for uid, user in users.items():
        if user["email"] == email:
            return {"success": False, "message": "Email already registered"}

    # Validate password policy
    if len(password) < 7:
        return {"success": False, "message": "Password must be at least 7 characters"}
    if not re.search(r"[A-Z]", password):
        return {"success": False, "message": "Password must include at least one uppercase letter"}
    if not re.search(r"[0-9]", password):
        return {"success": False, "message": "Password must include at least one digit"}
    if not re.search(r"[^A-Za-z0-9]", password):
        return {"success": False, "message": "Password must include at least one special character"}

    # Create new user
    user_id = str(uuid.uuid4())
    users[user_id] = {
        "email": email,
        "password_hash": _hash_password(password),
        "name": name or "",
        "phone": phone or "",
        "theme": "light",
        "security_question": security_question or "",
        "security_answer_hash": _hash_password((security_answer or "").lower().strip()),
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "is_primary": primary_account,
        "devices": {},  # {device_id: {name, last_seen}}
        "caretakers": [],  # list of user_ids with access
        "family": [],  # list of user_ids in family
    }

    _save_users(users)
    return {"success": True, "message": "Account created", "user_id": user_id}

def user_login(email: str, password: str) -> Dict:
    """Authenticate user. Returns {success, message, user_id}."""
    users = _load_users()
    
    for uid, user in users.items():
        if user["email"] == email:
            if user["password_hash"] == _hash_password(password):
                return {"success": True, "message": "Login successful", "user_id": uid}
            else:
                return {"success": False, "message": "Incorrect password"}
    
    return {"success": False, "message": "Email not found"}

def register_device(user_id: str, device_id: str, device_name: str) -> Dict:
    """Register a device for a user (e.g., family member's tablet)."""
    users = _load_users()
    
    if user_id not in users:
        return {"success": False, "message": "User not found"}
    
    users[user_id]["devices"][device_id] = {
        "name": device_name,
        "registered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    
    _save_users(users)
    return {"success": True, "message": f"Device '{device_name}' registered"}

def get_user_devices(user_id: str) -> List[Dict]:
    """Get all devices registered for a user."""
    users = _load_users()
    if user_id not in users:
        return []
    return [{"id": did, **info} for did, info in users[user_id]["devices"].items()]

def add_caretaker(user_id: str, caretaker_email: str) -> Dict:
    """Add a caretaker (family member) with access to this user's account."""
    users = _load_users()
    
    if user_id not in users:
        return {"success": False, "message": "User not found"}
    
    # Find caretaker by email
    caretaker_id = None
    for uid, user in users.items():
        if user["email"] == caretaker_email:
            caretaker_id = uid
            break
    
    if not caretaker_id:
        return {"success": False, "message": "Caretaker email not found"}
    
    if caretaker_id not in users[user_id]["caretakers"]:
        users[user_id]["caretakers"].append(caretaker_id)
        _save_users(users)
        return {"success": True, "message": f"Caretaker {caretaker_email} added"}
    
    return {"success": False, "message": "Caretaker already added"}

def get_accessible_accounts(user_id: str) -> List[str]:
    """Get list of user_ids this user can access (their own + caretaker access)."""
    users = _load_users()
    accessible = [user_id]  # Own account
    
    # Find accounts where this user is a caretaker
    for uid, user in users.items():
        if user_id in user["caretakers"]:
            accessible.append(uid)
    
    return accessible

def set_user_theme(user_id: str, theme: str) -> Dict:
    """Set theme preference for a user ('light' or 'dark')."""
    users = _load_users()
    if user_id not in users:
        return {"success": False, "message": "User not found"}
    users[user_id]["theme"] = theme if theme in ("light", "dark") else "light"
    _save_users(users)
    return {"success": True, "message": "Theme updated"}

def get_user_profile(user_id: str) -> Dict:
    """Return profile info for a user (public fields)."""
    users = _load_users()
    user = users.get(user_id)
    if not user:
        return {}
    return {"email": user.get("email"), "name": user.get("name"), "phone": user.get("phone"), "theme": user.get("theme", "light")}

def get_user_medicines(user_id: str) -> List[Dict]:
    """Get list of medicines for a specific user."""
    users = _load_users()
    user = users.get(user_id)
    if not user:
        return []
    return user.get("medicines", [])

def set_user_medicines(user_id: str, medicines: List[Dict]) -> bool:
    """Set medicines for a specific user."""
    users = _load_users()
    if user_id not in users:
        return False
    users[user_id]["medicines"] = medicines
    _save_users(users)
    return True

def verify_security_answer(email: str, provided_answer: str) -> Dict:
    """Verify security answer for password reset. Returns {success, message}."""
    users = _load_users()
    
    for uid, user in users.items():
        if user["email"] == email:
            # Normalize: lowercase and strip both answer and provided answer
            stored_hash = user.get("security_answer_hash", "")
            provided_normalized = _hash_password(provided_answer.lower().strip())
            if stored_hash == provided_normalized:
                return {"success": True, "message": "Security answer verified", "user_id": uid}
            else:
                return {"success": False, "message": "Security answer is incorrect"}
    
    return {"success": False, "message": "Email not found"}

def reset_password(user_id: str, new_password: str) -> Dict:
    """Reset password for a user after security verification."""
    import re
    users = _load_users()
    
    if user_id not in users:
        return {"success": False, "message": "User not found"}
    
    # Validate new password
    if len(new_password) < 7:
        return {"success": False, "message": "Password must be at least 7 characters"}
    if not re.search(r"[A-Z]", new_password):
        return {"success": False, "message": "Password must include at least one uppercase letter"}
    if not re.search(r"[0-9]", new_password):
        return {"success": False, "message": "Password must include at least one digit"}
    if not re.search(r"[^A-Za-z0-9]", new_password):
        return {"success": False, "message": "Password must include at least one special character"}
    
    users[user_id]["password_hash"] = _hash_password(new_password)
    _save_users(users)
    return {"success": True, "message": "Password reset successfully"}

def _select_voice_for_language(engine, language: str):
    """Try to pick a voice matching the requested language from pyttsx3 voices."""
    if not _HAS_PYTTSX3:
        return None

    language = (language or "").lower()
    voices = engine.getProperty("voices") or []

    # Preferred matching: check voice.languages, voice.id, voice.name for language code or name
    for v in voices:
        try:
            langs = []
            if hasattr(v, "languages") and v.languages:
                # languages can be like [b'\x05en_GB'] or ['en_US']
                for lv in v.languages:
                    try:
                        langs.append(lv.decode() if isinstance(lv, bytes) else str(lv))
                    except Exception:
                        pass
            name = (v.name or "").lower()
            vid = (v.id or "").lower()
            joined = " ".join(langs + [name, vid])
            if language in joined or language.replace("-", "_") in joined:
                return v.id
        except Exception:
            continue

    # Best-effort fallbacks by common language-name substring
    fallback_map = {
        "en": ["english", "en_"] ,
        "hi": ["hindi", "hi_"] ,
        "it": ["italian", "it_"] ,
        "de": ["german", "de_"] ,
        "fr": ["french", "fr_"] ,
        "es": ["spanish", "es_"] ,
    }
    checks = fallback_map.get(language, [])
    for v in voices:
        try:
            name = (v.name or "").lower()
            vid = (v.id or "").lower()
            for chk in checks:
                if chk in name or chk in vid:
                    return v.id
        except Exception:
            continue

    return None


def speak_text(text: str, language: str):
    """Speak `text` in the requested `language` using pyttsx3 when possible, otherwise macOS `say`.

    This function speaks the exact `text` passed in.
    """
    if not text:
        return

    # Try pyttsx3 first for better voice control
    if _HAS_PYTTSX3:
        try:
            engine = pyttsx3.init()
            voice_id = _select_voice_for_language(engine, language)
            if voice_id:
                try:
                    engine.setProperty("voice", voice_id)
                except Exception:
                    pass
            # Speak the exact text
            engine.say(text)
            engine.runAndWait()
            return
        except Exception:
            # If pyttsx3 fails for any reason, fall back to macOS `say`
            pass

    # Fallback to macOS `say` command
    voice = None
    if language == "en":
        voice = "Samantha"
    elif language == "hi":
        voice = "Lekha"
    elif language == "it":
        voice = "Alice"
    elif language == "de":
        voice = "Anna"
    elif language == "fr":
        voice = "Thomas"
    elif language == "es":
        voice = "Mónica"

    cmd = ["say"]
    if voice:
        cmd += ["-v", voice]
    cmd += [text]

    try:
        subprocess.run(cmd, check=False)
    except Exception:
        pass

def trigger(button: str, language: str, source: str, custom_text: str = None, device_id: str = "unknown", user_id: str = "default"):
    global HISTORY
    button = button.strip().upper()
    if custom_text:
        text = custom_text
    elif button not in CONFIG:
        text = f"Unknown button {button}"
    else:
        text = CONFIG[button]["texts"].get(language, CONFIG[button]["texts"]["en"])

    evt = Event(
        ts=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        source=source,
        button=button,
        language=language,
        text=text,
        device_id=device_id,
        user_id=user_id,
    )
    HISTORY.insert(0, evt)
    
    # Cleanup old events and persist
    _cleanup_old_events()
    _save_events_to_file(HISTORY)

    speak_text(text, language)
    return asdict(evt)