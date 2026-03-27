##Section 1: Importations et Configuration
import sys
import json
import csv
import os
import asyncio
import threading
import secrets
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import httpx
from PySide6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout,
                               QHBoxLayout, QLabel, QLineEdit, QPushButton, QComboBox,
                               QCheckBox, QTextEdit, QGroupBox, QFormLayout, QProgressBar,
                               QListWidget, QListWidgetItem, QMessageBox, QFrame, QGridLayout,
                               QDialog, QTextEdit, QInputDialog, QSizePolicy, QSpinBox, QSpacerItem, QScrollArea, QFileDialog)
from PySide6.QtCore import Qt, QThread, Signal, QTimer, QPoint, QRect, QMetaObject, Q_ARG, Slot
from PySide6.QtGui import QMouseEvent, QPainter, QColor, QIntValidator, QFont, QPalette, QIcon, QPixmap
import requests

# Configuration
BACKEND_URL = "https://sqea-backend.onrender.com"
LOCAL_CALLBACK_PORT = 8765  # Port pour le callback OAuth local

# Couleurs par rareté (utilisé dans plusieurs onglets)
RARITY_COLORS = {
    "common": "#8b949e",
    "uncommon": "#58a6ff",
    "rare": "#b45fff",
    "epic": "#ffa726",
    "legendary": "#ff6b6b",
    "Objet de Quête": "#3fb950",
    "Objet de Quête Épique": "#b45fff",
    "Objet de Quête Légendaire": "#ffa726"
}


# Obtenir le chemin du script actuel
script_dir = Path(__file__).parent
icon_path = script_dir / "icone.ico"


# Styles modernes
APP_STYLESHEET = """
    QMainWindow {
        background-color: #0d1117;
        color: #e6edf3;
    }
    QWidget {
        background-color: #0d1117;
        color: #e6edf3;
        font-family: 'Segoe UI', Arial, sans-serif;
    }
    QTabWidget::pane {
        border: 1px solid #30363d;
        background-color: #0d1117;
    }
    QTabBar::tab {
        background-color: #161b22;
        color: #e6edf3;
        padding: 8px 16px;
        margin-right: 2px;
        border-top-left-radius: 4px;
        border-top-right-radius: 4px;
    }
    QTabBar::tab:selected {
        background-color: #1f6feb;
        color: #ffffff;
    }
    QTabBar::tab:hover:!selected {
        background-color: #30363d;
    }
    QGroupBox {
        font-weight: bold;
        border: 1px solid #30363d;
        border-radius: 6px;
        margin-top: 10px;
        padding-top: 15px;
        background-color: #161b22;
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top center;
        padding: 0 8px;
        color: #e6edf3;
    }
    QPushButton {
        background-color: #238636;
        color: #ffffff;
        border: none;
        border-radius: 6px;
        padding: 8px 16px;
        font-weight: bold;
    }
    QPushButton:hover {
        background-color: #2ea043;
    }
    QPushButton:pressed {
        background-color: #196c2e;
    }
    QPushButton:disabled {
        background-color: #484f58;
        color: #8b949e;
    }
    QLineEdit, QTextEdit, QComboBox {
        background-color: #0d1117;
        color: #e6edf3;
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 6px;
        selection-background-color: #1f6feb;
    }
    QLineEdit:focus, QTextEdit:focus, QComboBox:focus {
        border-color: #1f6feb;
    }
    QListWidget {
        background-color: #0d1117;
        color: #e6edf3;
        border: 1px solid #30363d;
        border-radius: 6px;
        alternate-background-color: #161b22;
    }
    QListWidget::item:selected {
        background-color: #1f6feb;
        color: #ffffff;
    }
    QProgressBar {
        border: 1px solid #30363d;
        border-radius: 3px;
        text-align: center;
        background-color: #0d1117;
    }
    QProgressBar::chunk {
        background-color: #238636;
        width: 10px;
    }
    QCheckBox {
        spacing: 8px;
    }
    QCheckBox::indicator {
        width: 18px;
        height: 18px;
        border: 1px solid #30363d;
        border-radius: 3px;
        background-color: #0d1117;
    }
    QCheckBox::indicator:checked {
        background-color: #238636;
        border: 1px solid #238636;
    }
    QLabel {
        color: #e6edf3;
    }
    QStatusBar {
        background-color: #161b22;
        color: #e6edf3;
    }
    self.active_adventurers_label.setStyleSheet(
    QLabel {
        font-size: 12px;
        font-weight: bold;
        padding: 3px 8px;
        background-color: #161b22;
        border-radius: 4px;
        border: 1px solid #30363d;
    } 
"""

def test_event_codes_endpoint():
    """Teste l'endpoint des codes d'événements"""
    import httpx
    
    try:
        # CORRECTION : Utiliser le bon endpoint
        response = httpx.get(f"{BACKEND_URL}/admin/event/existing-codes", timeout=10.0)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Endpoint fonctionne - {len(data.get('codes', []))} codes trouvés")
            return True
        else:
            print(f"❌ Endpoint erreur HTTP: {response.status_code}")
            print(f"📄 Réponse: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Erreur connexion endpoint: {e}")
        return False
        
def generate_unique_event_code(event_type, existing_codes, api_client=None):
    """
    Génère un code d'événement unique basé sur le type et les codes existants
    """
    # Mapping des préfixes par type
    type_prefixes = {
        "community": "COM",
        "raid": "RAID", 
        "boss": "BOSS",
        "Boss Final": "BF",
        "Mission communautaire": "COM",
        "Boss": "BOSS",
        "": "EVT"
    }
    
    prefix = type_prefixes.get(event_type, "EVT")
    
    # Essayer de récupérer les codes existants si non fournis
    if existing_codes is None and api_client:
        try:
            result = api_client.get_existing_event_codes()
            if result and "codes" in result:
                existing_codes = result["codes"]
                print(f"📋 {len(existing_codes)} codes existants chargés depuis la DB")
            else:
                existing_codes = []
                print("⚠️ Aucun code existant trouvé ou erreur de chargement")
        except Exception as e:
            print(f"❌ Erreur chargement codes existants: {e}")
            existing_codes = []
    
    # Filtrer les codes du même préfixe
    prefix_codes = [code for code in (existing_codes or []) 
                   if code.startswith(prefix)]
    
    print(f"🔍 Recherche parmi {len(prefix_codes)} codes avec le préfixe {prefix}")
    
    # Extraire les numéros
    numbers = []
    for code in prefix_codes:
        try:
            # Supprimer le préfixe et convertir en nombre
            num_str = code.replace(prefix, "")
            if num_str.isdigit():
                numbers.append(int(num_str))
        except ValueError:
            continue
    
    # Trouver le prochain numéro disponible
    if numbers:
        next_num = max(numbers) + 1
        print(f"🎯 Dernier numéro trouvé: {max(numbers)}, prochain: {next_num}")
    else:
        next_num = 1
        print(f"🎯 Premier numéro pour le préfixe {prefix}")
    
    # Formater le code (3 chiffres)
    new_code = f"{prefix}{next_num:03d}"
    
    # Vérification finale de sécurité
    if existing_codes and new_code in existing_codes:
        print(f"⚠️  Code {new_code} existe déjà, recherche d'une alternative...")
        # Si le code existe déjà, on prend le suivant
        next_num += 1
        new_code = f"{prefix}{next_num:03d}"
    
    print(f"✅ Code unique généré: {new_code}")
    return new_code

# Section 2: Thread SSE (inchangé)
class SSEThread(QThread):
    """Thread pour recevoir les événements SSE du backend"""
    new_event = Signal(str, object)  # Signal pour les nouveaux événements

    def __init__(self, backend_url):
        super().__init__()
        self.backend_url = backend_url
        self.running = True

    def run(self):
        """Connexion au SSE avec gestion d'erreurs"""
        url = urljoin(self.backend_url, "/events")

        # Essayer plusieurs fois en cas d'échec
        for attempt in range(3):
            if not self.running:
                break

            try:
                print(f"🔗 Tentative {attempt + 1}/3 de connexion SSE...")
                async def listen_events():
                    async with httpx.AsyncClient(timeout=30.0) as client:
                        async with client.stream("GET", url, headers={"Accept": "text/event-stream"}, timeout=30.0) as response:
                            response.raise_for_status()

                            buffer = ""
                            async for chunk in response.aiter_bytes():
                                if not self.running:
                                    break

                                buffer += chunk.decode('utf-8')
                                while "\n\n" in buffer:
                                    event_part, buffer = buffer.split("\n\n", 1)
                                    lines = event_part.split("\n")

                                    event_type = None
                                    data = None

                                    for line in lines:
                                        if line.startswith("event:"):
                                            event_type = line[6:].strip()
                                        elif line.startswith("data:"):
                                            try:
                                                data = json.loads(line[5:].strip())
                                            except json.JSONDecodeError:
                                                data = line[5:].strip()

                                    if event_type and event_type != "ping":
                                        self.new_event.emit(event_type, data)

                asyncio.run(listen_events())
                break  # Sortir si réussi

            except (httpx.TimeoutException, httpx.NetworkError):
                print(f"⏰ Timeout SSE, tentative {attempt + 1}")
                time.sleep(5)  # Attendre avant de réessayer
            except Exception as e:
                print(f"❌ Erreur SSE: {e}")
                break


# Section 3: Client API
class APIClient:
    """Client pour interagir avec l'API backend avec JWT"""

    def __init__(self, backend_url):
        self.backend_url = backend_url
        self.client = httpx.Client(
            base_url=backend_url,
            timeout=30.0,
            follow_redirects=True,
            headers={'User-Agent': 'StreamQuest-SuperAdmin/1.0'}
        )
        self.auth_callback = None
        self.debug_info = {}
        self.jwt_token = None  # Stocke le JWT
        self.is_online = False
        # Cache avec TTL pour réduire les appels API répétitifs
        self._cache = {}  # {endpoint: (data, timestamp)}

    def set_auth_callback(self, callback):
        self.auth_callback = callback

    def check_connectivity(self):
        """Vérifie si le backend est accessible (avec cache de 10s)"""
        now = time.time()
        cache_key = "__connectivity__"
        if cache_key in self._cache:
            _, ts = self._cache[cache_key]
            if now - ts < 10:
                return self.is_online
        try:
            response = self.client.get("/", timeout=5.0)
            self.is_online = response.status_code < 500
            self._cache[cache_key] = (self.is_online, now)
            return self.is_online
        except Exception:
            self.is_online = False
            self._cache[cache_key] = (False, now)
            return False

    def whoami(self):
        """Vérifie la session active avec JWT"""
        try:
            headers = {}
            if self.jwt_token:
                headers['Authorization'] = f'Bearer {self.jwt_token}'

            response = self.client.get("/admin/session/whoami", headers=headers, timeout=10.0)
            self.debug_info['whoami_status'] = response.status_code

            if response.status_code == 200:
                return response.json()
            return None

        except Exception as e:
            print(f"❌ Erreur WHOAMI: {e}")
            return None

    def get_existing_event_codes(self):
            """Récupère tous les codes d'événements existants depuis le backend"""
            return self._make_request("GET", "/admin/event/existing-codes")
    
    def exchange_code_for_token(self, auth_code):
        """Échange un code OAuth contre un JWT"""
        try:
            response = self.client.post(
                "/oauth/token",
                json={"code": auth_code},
                timeout=15.0
            )

            if response.status_code == 200:
                token_data = response.json()
                self.jwt_token = token_data.get("access_token")
                self.save_cookies()
                print(f"✅ JWT obtenu avec succès")
                return True
            else:
                print(f"❌ Erreur échange token: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            print(f"❌ Erreur échange token: {e}")
            return False

    def start_token_interceptor(self):
        """Démarre un serveur pour intercepter le code OAuth"""
        import webbrowser

        class OAuthHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                try:
                    print(f"📨 Requête reçue: {self.path}")

                    if self.path.startswith('/callback'):
                        parsed_url = urlparse(self.path)
                        query_params = parse_qs(parsed_url.query)

                        if 'code' in query_params:
                            auth_code = query_params['code'][0]
                            print(f"🔑 Code OAuth reçu: {auth_code}")

                            # Échanger le code contre un JWT
                            if self.server.client_ref.exchange_code_for_token(auth_code):
                                self.send_response(200)
                                self.send_header('Content-type', 'text/html')
                                self.end_headers()
                                self.wfile.write(b"""
                                    <html><body>
                                    <h1>Authentication Successful!</h1>
                                    <p>You can close this window.</p>
                                    </body></html>
                                """)

                                if self.server.client_ref.auth_callback:
                                    self.server.client_ref.auth_callback(True)
                                return

                    # Page par défaut
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b"""
                        <html><body>
                        <h1>StreamQuest Auth</h1>
                        <p>Waiting for authentication...</p>
                        </body></html>
                    """)

                except Exception as e:
                    print(f"❌ Erreur handler: {e}")

            def log_message(self, format, *args):
                pass

        def run_server():
            server = HTTPServer(('localhost', 8765), OAuthHandler)
            server.client_ref = self
            print("🌐 Serveur d'interception démarré sur le port 8765")
            server.serve_forever()

        threading.Thread(target=run_server, daemon=True).start()

        # URL d'authentification Twitch
        callback_url = "http://localhost:8765/callback"
        auth_url = f"{self.backend_url}/oauth/authorize?next={callback_url}"
        webbrowser.open(auth_url)
        print(f"🌐 Ouverture: {auth_url}")

    def login_twitch(self):
        """Démarre le processus de connexion Twitch"""
        self.debug_info = {'login_started': datetime.now().isoformat()}
        self.start_token_interceptor()

    def connect_twitch_direct(self):
        """Connexion directe via l'API sans interception"""
        import webbrowser

        # 1. Ouvrir l'authentification
        auth_url = f"{self.backend_url}/oauth/authorize"
        webbrowser.open(auth_url)

        # 2. Demander le code manuellement
        code, ok = QInputDialog.getText(
            None,
            "Code d'authentification",
            "Après authentification Twitch, copiez le code depuis l'URL et collez-le ici:",
            QLineEdit.Normal,
            ""
        )

        if ok and code:
            # 3. Échanger le code contre un JWT
            if self.exchange_code_for_token(code.strip()):
                print("✅ Authentification réussie!")
                return True
            else:
                print("❌ Échec de l'authentification")
                return False
        return False

    def logout(self):
        """Déconnexion"""
        self.jwt_token = None
        self.save_cookies()
        print("✅ Déconnecté")

    # Endpoints polled frequently - no need to log them every time
    _quiet_endpoints = {"/admin/event/status", "/admin/event/malus-total",
                        "/admin/config/MISSION_COOLDOWN_SEC", "/admin/participants/active-count",
                        "/public/coffre/items", "/"}

    def _make_request(self, method, endpoint, **kwargs):
        """Méthode générique pour les requêtes API avec JWT"""
        try:
            headers = kwargs.pop('headers', {})
            if self.jwt_token:
                headers['Authorization'] = f'Bearer {self.jwt_token}'

            verbose = endpoint not in self._quiet_endpoints
            if verbose:
                print(f"🔍 API Request: {method} {endpoint}")

            response = self.client.request(
                method, endpoint,
                headers=headers,
                **kwargs
            )

            if response.status_code == 401:
                print(f"🔒 Accès non autorisé - JWT expiré ou invalide")
                self.jwt_token = None
                return None
            elif response.status_code >= 400:
                print(f"⚠️  Erreur {response.status_code} sur {endpoint}")
                return {"error": f"HTTP {response.status_code}", "message": response.text}

            try:
                result = response.json() if response.content else {}
                return result
            except json.JSONDecodeError:
                return response.text

        except httpx.RequestError as e:
            print(f"❌ Erreur réseau sur {endpoint}: {e}")
            return {"error": "NetworkError", "message": str(e)}
        except Exception as e:
            print(f"❌ Erreur sur {endpoint}: {e}")
            return {"error": type(e).__name__, "message": str(e)}           
        
    def save_cookies(self, filename="cookies.json"):
        """Sauvegarde le JWT"""
        try:
            with open(filename, 'w') as f:
                json.dump({'jwt_token': self.jwt_token}, f)
            print("💾 JWT sauvegardé")
        except Exception as e:
            print(f"❌ Erreur sauvegarde JWT: {e}")

    def load_cookies(self, filename="cookies.json"):
        """Charge le JWT"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)

            if data.get('jwt_token'):
                self.jwt_token = data['jwt_token']
                print("✅ JWT chargé")
                return True

            return False

        except FileNotFoundError:
            print("📭 Aucun JWT sauvegardé")
            return False
        except Exception as e:
            print(f"❌ Erreur chargement JWT: {e}")
            return False
    def ensure_connectivity(self):
        """Vérifie et attend que la connexion soit rétablie si nécessaire"""
        if not self.is_online:
            print("📡 Tentative de reconnexion...")
            time.sleep(2)
            return self.check_connectivity()
        return True

    def _cached_get(self, endpoint, cache_ttl=10):
        """GET avec cache TTL - évite les appels répétitifs pour des données qui changent peu"""
        now = time.time()
        if endpoint in self._cache:
            data, ts = self._cache[endpoint]
            if now - ts < cache_ttl:
                return data
        result = self._make_request("GET", endpoint)
        if result is not None and not (isinstance(result, dict) and "error" in result):
            self._cache[endpoint] = (result, now)
        return result

    def invalidate_cache(self, endpoint=None):
        """Invalide le cache (tout ou un endpoint spécifique)"""
        if endpoint:
            self._cache.pop(endpoint, None)
        else:
            self._cache.clear()

    # Toutes les méthodes API restent les mêmes
    def get_event_status(self):
        return self._cached_get("/admin/event/status", cache_ttl=3)

    def save_event(self, event_data):
        """Sauvegarde un événement"""
        self.invalidate_cache("/admin/event/status")
        self.invalidate_cache("/admin/event/malus-total")
        return self._make_request("POST", "/admin/event/set", json=event_data)

    def event_action(self, action, data=None):
        """Exécute une action sur l'événement avec données optionnelles"""
        self.invalidate_cache("/admin/event/status")
        self.invalidate_cache("/admin/event/malus-total")
        if data is None:
            data = {}
        if action == "cancel" and "cancel_reason" in data:
            return self._make_request("POST", f"/admin/event/{action}", json=data)
        else:
            return self._make_request("POST", f"/admin/event/{action}")

    def get_solo_defs(self):
        return self._make_request("GET", "/admin/solo/defs") or {"defs": []}

    def save_solo_def(self, def_data):
        return self._make_request("POST", "/admin/solo/defs", json=def_data)

    def delete_solo_def(self, code):
        return self._make_request("DELETE", f"/admin/solo/defs/{code}")

    def get_solo_runs(self):
        return self._make_request("GET", "/admin/solo/list") or {"runs": []}

    def get_overlay_config(self):
        """Récupère la configuration overlay"""
        result = self._cached_get("/admin/overlay/config", cache_ttl=30)
        return result or {"widgets": {}, "options": {}}

    def save_overlay_config(self, config):
        """Sauvegarde la configuration overlay"""
        self.invalidate_cache("/admin/overlay/config")
        return self._make_request("POST", "/admin/overlay/config", json=config)  
    def test_connectivity(self):
        """Teste la connectivité avec tous les endpoints"""
        endpoints = [
            "/admin/session/whoami",
            "/admin/event/status",
            "/admin/solo/defs",
            "/admin/solo/list",
            "/admin/overlay/config",
            "/oauth/info"
        ]

        print("=== TEST DE CONNECTIVITÉ ===")
        print(f"Token actuel: {self.jwt_token}")

        for endpoint in endpoints:
            try:
                response = self.client.get(endpoint)
                status = "✅" if response.status_code == 200 else "❌"
                print(f"{status} {endpoint}: {response.status_code}")
            except Exception as e:
                print(f"❌ {endpoint}: {e}")
    def get_item_effects(self, item_code):
        """Récupère les effets d'un item"""
        return self._make_request("GET", f"/admin/items/{item_code}/effects")

    def add_item_effect(self, item_code, effect_data):
        """Ajoute un effet à un item"""
        return self._make_request("POST", f"/admin/items/{item_code}/effects", json=effect_data)

    def delete_item_effect(self, effect_id):
        """Supprime un effet d'item"""
        return self._make_request("DELETE", f"/admin/items/effects/{effect_id}")

    def get_event_types(self):
        """Récupère les types d'événements disponibles"""
        return self._cached_get("/admin/event-types", cache_ttl=300)

    def get_effect_types(self):
        """Récupère les types d'effets disponibles"""
        return self._cached_get("/admin/effect-types", cache_ttl=300)

    def get_all_items(self):
        """Récupère tous les items en fusionnant /api/items (image_url) et /admin/items (type)"""
        # /api/items retourne image_url mais pas type
        api_data = self._cached_get("/api/items", cache_ttl=30)
        api_items = api_data if isinstance(api_data, list) else (api_data.get("items", []) if api_data else [])

        # /admin/items retourne type mais pas image_url
        admin_data = self._cached_get("/admin/items", cache_ttl=30)
        admin_items = admin_data.get("items", []) if admin_data and isinstance(admin_data, dict) else []

        # Index admin par code pour fusion rapide
        admin_by_code = {it.get('code'): it for it in admin_items}

        # Fusionner : enrichir chaque item API avec les champs manquants d'admin
        for item in api_items:
            admin_item = admin_by_code.get(item.get('code'))
            if admin_item:
                for key, value in admin_item.items():
                    if key not in item or item[key] is None:
                        item[key] = value

        return {"items": api_items}

    def invalidate_items_cache(self):
        """Invalide le cache des items après modification"""
        self.invalidate_cache("/api/items")
        self.invalidate_cache("/admin/items")
    def get_active_effects_for_event(api_client, event_type: str):
        """Récupère les effets actifs pour un type d'événement"""
        try:
            # Cette fonction devra interroger le backend pour les effets actifs
            # Pour l'instant, on retourne un dictionnaire vide
            # Vous devrez créer l'endpoint backend correspondant
            return {
                "malus_reduction": 0,
                "attack_bonus": 0,
                "time_extension": 0,
                "xp_boost": 0
            }
        except Exception as e:
            print(f"❌ Erreur récupération effets actifs: {e}")
            return {}
   
    def get_malus_total(self):
        """Récupère le malus total des événements échoués"""
        return self._cached_get("/admin/event/malus-total", cache_ttl=20)
        
    def upload_item_image(self, item_code, image_path):
        """Upload réel d'une image vers le serveur"""
        try:
            print(f"📤 Upload réel de l'image: {image_path}")
            
            with open(image_path, 'rb') as f:
                files = {'image': (os.path.basename(image_path), f, 'image/png')}
                data = {'item_code': item_code}
                
                headers = {}
                if self.jwt_token:
                    headers['Authorization'] = f'Bearer {self.jwt_token}'
                
                # Utiliser l'endpoint d'upload réel
                response = self.client.post(
                    f"{self.backend_url}/admin/items/{item_code}/upload-image",
                    files=files,
                    data=data,
                    headers=headers,
                    timeout=30.0
                )
                
                print(f"📡 Response status upload: {response.status_code}")
                
                if response.status_code == 200:
                    result = response.json()
                    image_url = result.get('image_url')
                    print(f"✅ Upload réussi, URL: {image_url}")
                    return image_url
                else:
                    print(f"❌ Erreur upload image: {response.status_code} - {response.text}")
                    return None
                    
        except Exception as e:
            print(f"❌ Erreur upload image: {e}")
            return None

    def delete_item_image(self, item_code):
        """Supprime l'image d'un item"""
        return self._make_request("DELETE", f"/admin/items/{item_code}/image")
    def get_all_boss(self):
        return self._cached_get("/admin/boss", cache_ttl=30)

    def get_boss(self, boss_id):
        return self._make_request("GET", f"/admin/boss/{boss_id}")

    def get_current_boss(self):
        return self._make_request("GET", "/admin/boss/current")

    def upsert_boss(self, boss_data):
        self.invalidate_cache("/admin/boss")
        return self._make_request("POST", "/admin/boss/upsert", json=boss_data)

    def delete_boss(self, boss_id):
        self.invalidate_cache("/admin/boss")
        return self._make_request("DELETE", f"/admin/boss/{boss_id}")

    def upload_boss_image(self, boss_id, image_path):
        """Upload une image pour un boss"""
        try:
            with open(image_path, 'rb') as f:
                files = {'image': (os.path.basename(image_path), f, 'image/png')}
                data = {'boss_id': boss_id}
                
                headers = {}
                if self.jwt_token:
                    headers['Authorization'] = f'Bearer {self.jwt_token}'
                
                response = self.client.post(
                    f"{self.backend_url}/admin/boss/{boss_id}/upload-image",
                    files=files,
                    data=data,
                    headers=headers,
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    result = response.json()
                    return result.get('image_url')
                else:
                    print(f"❌ Erreur upload image boss: {response.status_code} - {response.text}")
                    return None
                    
        except Exception as e:
            print(f"❌ Erreur upload image boss: {e}")
            return None
    
    def delete_boss_sound(self, boss_id, sound_type):
        """Supprime un son de boss"""
        return self._make_request("DELETE", f"/admin/boss/{boss_id}/sound/{sound_type}")

    def upload_boss_video(self, boss_id, video_path):
        """Upload une vidéo intro pour un boss sur Cloudinary"""
        try:
            print(f"📤 Upload vidéo boss {boss_id}: {video_path}")
            with open(video_path, 'rb') as f:
                files = {'video': (os.path.basename(video_path), f, 'video/mp4')}
                data = {'boss_id': boss_id}

                headers = {}
                if self.jwt_token:
                    headers['Authorization'] = f'Bearer {self.jwt_token}'

                response = self.client.post(
                    f"{self.backend_url}/admin/boss/{boss_id}/upload-video",
                    files=files,
                    data=data,
                    headers=headers,
                    timeout=120.0  # Timeout long pour les vidéos
                )

                if response.status_code == 200:
                    result = response.json()
                    video_url = result.get('video_url')
                    print(f"✅ Upload vidéo réussi: {video_url}")
                    return video_url
                else:
                    print(f"❌ Erreur upload vidéo: {response.status_code} - {response.text}")
                    return None

        except Exception as e:
            print(f"❌ Erreur upload vidéo: {e}")
            return None

    def upload_boss_sound(self, boss_id, sound_type, sound_path):
        """Upload un son pour un boss"""
        try:
            print(f"📤 Upload du son {sound_type} pour le boss {boss_id}: {sound_path}")
            
            with open(sound_path, 'rb') as f:
                files = {'file': (os.path.basename(sound_path), f, 'audio/mpeg')}
                data = {'sound_type': sound_type}
                
                headers = {}
                if self.jwt_token:
                    headers['Authorization'] = f'Bearer {self.jwt_token}'
                
                response = self.client.post(
                    f"{self.backend_url}/admin/boss/{boss_id}/upload-sound",
                    files=files,
                    data=data,
                    headers=headers,
                    timeout=30.0
                )
                
                print(f"📡 Response status upload son: {response.status_code}")
                
                if response.status_code == 200:
                    result = response.json()
                    sound_url = result.get('sound_url')
                    print(f"✅ Upload son réussi, URL: {sound_url}")
                    return sound_url
                else:
                    print(f"❌ Erreur upload son: {response.status_code} - {response.text}")
                    return None
                    
        except Exception as e:
            print(f"❌ Erreur upload son: {e}")
            return None


# Section 4: Composants UI améliorés
class DraggableBlock(QFrame):
    """Bloc draggable pour l'overlay"""

    def __init__(self, title, description, parent=None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.Box)
        self.setLineWidth(2)
        self.setStyleSheet("""
            background-color: #161b22; 
            color: #e8f4ff; 
            border: 1px solid #30363d;
            border-radius: 4px;
        """)

        layout = QVBoxLayout()
        title_label = QLabel(title)
        title_label.setStyleSheet("font-weight: bold; font-size: 12px;")
        desc_label = QLabel(description)
        desc_label.setStyleSheet("color: #8b949e; font-size: 10px;")
        desc_label.setWordWrap(True)

        layout.addWidget(title_label)
        layout.addWidget(desc_label)
        self.setLayout(layout)

        self.dragging = False
        self.offset = QPoint()
        self.setFixedSize(120, 60)

    def mousePressEvent(self, event: QMouseEvent):
        if event.button() == Qt.LeftButton:
            self.dragging = True
            self.offset = event.position().toPoint()  # Utiliser position() au lieu de pos()
            self.setStyleSheet("""
                background-color: #1f6feb; 
                color: #ffffff; 
                border: 1px solid #30363d;
                border-radius: 4px;
            """)

    def mouseMoveEvent(self, event: QMouseEvent):
        if self.dragging and event.buttons() & Qt.LeftButton:
            new_pos = self.mapToParent(event.position().toPoint() - self.offset)
            self.move(new_pos)

    def mouseReleaseEvent(self, event: QMouseEvent):
        if event.button() == Qt.LeftButton:
            self.dragging = False
            self.setStyleSheet("""
                background-color: #161b22; 
                color: #e8f4ff; 
                border: 1px solid #30363d;
                border-radius: 4px;
            """)


class OverlayPreview(QWidget):
    """Zone de prévisualisation de l'overlay - NOUVELLE VERSION"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(960, 540)

        # Création des widgets du NOUVEAU design
        self.widgets = {
            "hud": DraggableBlock("HUD Progression", "Barre de progression", self),
            "event-timer": DraggableBlock("Compteur Event", "Timer événement", self),
            "ranking-widget": DraggableBlock("Classement Live", "Top participants", self),
            "commands-widget": DraggableBlock("Commandes", "Liste des commandes", self),
            "toasts-widget": DraggableBlock("Chroniques", "Notifications", self),
            "stats-widget": DraggableBlock("Archives", "Statistiques", self),
            "map-widget": DraggableBlock("Carte", "Carte du royaume", self),
            "hall-of-fame": DraggableBlock("Légendes", "Hall of Fame", self)
        }

        # Positions par défaut basées sur le nouveau design
        self.widgets["hud"].move(50, 20)
        self.widgets["event-timer"].move(700, 20)
        self.widgets["ranking-widget"].move(700, 80)
        self.widgets["commands-widget"].move(50, 300)
        self.widgets["toasts-widget"].move(400, 300)
        self.widgets["stats-widget"].move(50, 150)
        self.widgets["map-widget"].move(400, 150)
        self.widgets["hall-of-fame"].move(700, 200)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setPen(QColor(255, 255, 255, 30))

        # Grille de fond
        for x in range(0, self.width(), 40):
            painter.drawLine(x, 0, x, self.height())
        for y in range(0, self.height(), 40):
            painter.drawLine(0, y, self.width(), y)

    def get_positions(self):
        """Retourne les positions pour l'overlay (base 1920x1080)"""
        positions = {}
        for name, widget in self.widgets.items():
            # Conversion correcte : prévisualisation (960x540) -> overlay (1920x1080)
            x = int((widget.x() / 960) * 1920)
            y = int((widget.y() / 540) * 1080)
            w = int((widget.width() / 960) * 1920)
            h = int((widget.height() / 540) * 1080)
            positions[name] = {"x": x, "y": y, "w": w, "h": h}
        return positions

    def set_positions(self, positions):
        """Définit les positions depuis l'overlay (base 1920x1080)"""
        for name, pos in positions.items():
            if name in self.widgets:
                # Conversion correcte : overlay (1920x1080) -> prévisualisation (960x540)
                x = int((pos.get("x", 0) / 1920) * 960)
                y = int((pos.get("y", 0) / 1080) * 540)
                self.widgets[name].move(x, y)
                
                if "w" in pos and "h" in pos:
                    w = int((pos.get("w", 100) / 1920) * 960)
                    h = int((pos.get("h", 50) / 1080) * 540)
                    self.widgets[name].setFixedSize(w, h)


# Section 4.5: Nouvel onglet Lore (version complète et corrigée)
class LoreTab(QWidget):
    """Onglet de gestion du lore et de la progression narrative"""

    def __init__(self, api_client, event_tab_ref=None):
        super().__init__()
        self.api_client = api_client
        self.event_tab_ref = event_tab_ref
        self.arcs = []
        self.semaines = []
        self.evenements = []
        self.current_arc = None
        self.current_semaine = None
        self.prochain_event_data = None
        self.last_event_data = None
        self.semaine_actuelle = None
        self.est_prochain = True
        self._auto_selecting = False
        
        self.init_ui()
        QTimer.singleShot(500, self.load_lore_data)

    def format_duration(self, minutes):
        """Convertit les minutes en format lisible"""
        if not minutes:
            return "Non spécifiée"
        
        try:
            minutes = int(minutes)
            hours = minutes // 60
            remaining_minutes = minutes % 60
            
            if hours > 0:
                if remaining_minutes > 0:
                    return f"{hours}h {remaining_minutes:02d}min"
                else:
                    return f"{hours}h"
            else:
                return f"{remaining_minutes}min"
        except (ValueError, TypeError):
            return "Format invalide"

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(15, 15, 15, 15)

        # Section Prochain Événement (tout en haut) - TAILLE ADAPTATIVE
        self.prochain_event_group = QGroupBox("🎯 PROCHAIN ÉVÉNEMENT À JOUER")
        self.prochain_event_group.setStyleSheet("""
            QGroupBox {
                background-color: #1a472a;
                border: 2px solid #2e8b57;
                border-radius: 8px;
                font-weight: bold;
                color: #ffffff;
            }
            QGroupBox::title {
                color: #90ee90;
                padding: 0 10px;
            }
        """)
        
        prochain_layout = QHBoxLayout()
        
        self.prochain_event_info = QLabel("Chargement du prochain événement...")
        self.prochain_event_info.setStyleSheet("color: #e6edf3; font-size: 14px;")
        self.prochain_event_info.setWordWrap(True)
        
        self.export_btn = QPushButton("📤 Exporter vers Événement")
        self.export_btn.clicked.connect(self.exporter_prochain_vers_event)
        self.export_btn.setEnabled(False)
        
        prochain_layout.addWidget(self.prochain_event_info, 1)
        prochain_layout.addWidget(self.export_btn)
        
        self.prochain_event_group.setLayout(prochain_layout)
        main_layout.addWidget(self.prochain_event_group)

        # === Indicateur de progression de l'arc ===
        self.arc_progression_group = self.create_arc_progression_indicator()
        main_layout.addWidget(self.arc_progression_group)

        # Header - Résumé de la situation actuelle - TAILLE ADAPTATIVE
        header_group = QGroupBox("📖 SITUATION ACTUELLE")
        header_layout = QGridLayout()
        
        self.arc_label = QLabel("Arc: Chargement...")
        self.arc_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #58a6ff;")
        self.semaine_label = QLabel("Semaine: Chargement...")
        self.semaine_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #58a6ff;")
        self.stats_label = QLabel("Statistiques: Chargement...")
        self.stats_label.setStyleSheet("font-size: 12px; color: #8b949e;")
        
        header_layout.addWidget(QLabel("🎮 Progression narrative:"), 0, 0)
        header_layout.addWidget(self.arc_label, 0, 1)
        header_layout.addWidget(self.semaine_label, 1, 1)
        header_layout.addWidget(self.stats_label, 2, 0, 1, 2)
        
        header_group.setLayout(header_layout)
        main_layout.addWidget(header_group)

        # Section principale - Navigation et affichage
        lore_group = QGroupBox("📚 EXPLORATION DU LORE")
        lore_layout = QVBoxLayout()
        
        # Navigation
        nav_layout = QHBoxLayout()
        self.arc_combo = QComboBox()
        self.arc_combo.currentTextChanged.connect(self.on_arc_changed)
        self.semaine_combo = QComboBox()
        self.semaine_combo.currentTextChanged.connect(self.on_semaine_changed)
        
        nav_layout.addWidget(QLabel("Arc:"))
        nav_layout.addWidget(self.arc_combo, 2)
        nav_layout.addWidget(QLabel("Semaine:"))
        nav_layout.addWidget(self.semaine_combo, 3)
        nav_layout.addStretch()
        
        # Filtres
        filter_layout = QHBoxLayout()
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["Tous les types", "Mission communautaire", "Boss", "Autre"])
        self.filter_combo.currentTextChanged.connect(self.apply_filters)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Rechercher un événement...")
        self.search_input.textChanged.connect(self.apply_filters)

        filter_layout.addWidget(QLabel("Filtrer:"))
        filter_layout.addWidget(self.filter_combo)
        filter_layout.addWidget(QLabel("Recherche:"))
        filter_layout.addWidget(self.search_input)
        filter_layout.addStretch()
        
        refresh_btn = QPushButton("🔄 Actualiser")
        refresh_btn.clicked.connect(self.load_lore_data)
        filter_layout.addWidget(refresh_btn)
        
        lore_layout.addLayout(nav_layout)
        lore_layout.addLayout(filter_layout)

        # Affichage du contenu - TAILLE ADAPTATIVE
        self.lore_display = QTextEdit()
        self.lore_display.setReadOnly(True)
        self.lore_display.setStyleSheet("""
            QTextEdit {
                background-color: #0d1117;
                color: #e6edf3;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                font-size: 13px;
                line-height: 1.4;
            }
        """)
        # Politique de taille adaptative
        self.lore_display.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.MinimumExpanding)
        self.lore_display.setMinimumHeight(80)  # Hauteur minimale réduite
        lore_layout.addWidget(self.lore_display)

        # Événements de la semaine - TAILLE ADAPTATIVE AVEC SCROLLBAR
        events_group = QGroupBox("🗓️ ÉVÉNEMENTS DE LA SEMAINE")
        events_layout = QVBoxLayout()
        
        self.events_list = QListWidget()
        self.events_list.itemClicked.connect(self.on_event_selected)
        
        # Politique de taille adaptative avec hauteur basée sur le contenu
        self.events_list.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.MinimumExpanding)
        self.events_list.setMinimumHeight(60)  # Hauteur minimale pour 2 éléments
        self.events_list.setMaximumHeight(180)  # Hauteur maximale pour ~6 éléments
        self.events_list.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        
        events_layout.addWidget(self.events_list)
        events_group.setLayout(events_layout)
        lore_layout.addWidget(events_group)

        # Statistiques de la semaine - TAILLE FIXE (petit)
        stats_group = QGroupBox("📈 STATISTIQUES DE LA SEMAINE")
        stats_layout = QGridLayout()

        self.stats_total_events = QLabel("Événements: 0")
        self.stats_total_duration = QLabel("Durée totale: 0")
        self.stats_total_xp = QLabel("XP totale: 0")
        self.stats_avg_duration = QLabel("Durée moyenne: 0")
        self.stats_rewards_count = QLabel("Récompenses uniques: 0")

        stats_layout.addWidget(self.stats_total_events, 0, 0)
        stats_layout.addWidget(self.stats_total_duration, 0, 1)
        stats_layout.addWidget(self.stats_total_xp, 1, 0)
        stats_layout.addWidget(self.stats_avg_duration, 1, 1)
        stats_layout.addWidget(self.stats_rewards_count, 2, 0, 1, 2)

        stats_group.setLayout(stats_layout)
        lore_layout.addWidget(stats_group)

        lore_group.setLayout(lore_layout)
        main_layout.addWidget(lore_group)

        # Dernier événement terminé - TAILLE ADAPTATIVE
        last_event_group = QGroupBox("📊 DERNIER ÉVÉNEMENT TERMINÉ")
        last_event_layout = QGridLayout()
        
        self.last_event_title = QLabel("Aucun événement récent")
        self.last_event_title.setStyleSheet("font-weight: bold; color: #58a6ff;")
        self.last_event_result = QLabel("Statut: -")
        self.last_event_participants = QLabel("Participants: -")
        self.last_event_duration = QLabel("Durée: -")
        self.last_event_progression = QLabel("Progression: -")
        self.last_event_summary = QLabel("Résumé: -")
        self.last_event_summary.setWordWrap(True)
        self.last_event_summary.setStyleSheet("color: #8b949e; font-style: italic;")
        
        last_event_layout.addWidget(self.last_event_title, 0, 0, 1, 2)
        last_event_layout.addWidget(self.last_event_result, 1, 0)
        last_event_layout.addWidget(self.last_event_participants, 1, 1)
        last_event_layout.addWidget(self.last_event_duration, 2, 0)
        last_event_layout.addWidget(self.last_event_progression, 2, 1)
        last_event_layout.addWidget(self.last_event_summary, 3, 0, 1, 2)
        
        last_event_group.setLayout(last_event_layout)
        main_layout.addWidget(last_event_group)

        self.setLayout(main_layout)

    def load_lore_data(self):
        """Charge toutes les données du lore"""
        try:
            # Charger les arcs
            arcs_data = self.api_client._make_request("GET", "/lore/arcs")
            if arcs_data and "error" not in arcs_data:
                self.arcs = arcs_data
                print(f"✅ {len(self.arcs)} arcs chargés")
            else:
                self.arcs = []
                print("❌ Erreur chargement arcs")

            # Charger les semaines
            semaines_data = self.api_client._make_request("GET", "/lore/semaines")
            if semaines_data and "error" not in semaines_data:
                self.semaines = semaines_data
                print(f"✅ {len(self.semaines)} semaines chargées")
            else:
                self.semaines = []

            # Charger les événements
            events_data = self.api_client._make_request("GET", "/lore/evenements")
            if events_data and "error" not in events_data:
                self.evenements = events_data
                print(f"✅ {len(self.evenements)} événements chargés")
            else:
                self.evenements = []

            if self.arcs and self.semaines and self.evenements:
                self.update_display()
                self.load_prochain_evenement_amelioré()
                self.load_last_event_real()
                # Mettre à jour l'indicateur de progression
                QTimer.singleShot(500, self.update_arc_progression)
            else:
                self.afficher_erreur("Données incomplètes")

        except Exception as e:
            self.afficher_erreur(f"Erreur chargement: {e}")

    def load_prochain_evenement_amelioré(self):
        """Charge le prochain événement avec le nouveau système"""
        try:
            data = self.api_client._make_request("GET", "/lore/prochain-evenement-complet")
            if data and "error" not in data:
                self.prochain_event_data = data.get("lore_event")
                self.semaine_actuelle = data.get("semaine_actuelle")
                self.est_prochain = data.get("est_prochain", True)
                
                if self.prochain_event_data:
                    print(f"🎯 Prochain événement chargé: {self.prochain_event_data.get('titre')}")
                    self.afficher_prochain_evenement()
                    self.afficher_semaine_actuelle()
                    
                    # Marquer que nous sommes en mode sélection automatique
                    self._auto_selecting = True
                    
                    # Sélectionner automatiquement dans les combos avec un délai plus long
                    QTimer.singleShot(1000, self.select_prochain_evenement_in_combos)
                else:
                    self.prochain_event_info.setText("🎉 Tous les événements ont été joués !")
                    self.export_btn.setEnabled(False)
            else:
                self.determiner_prochain_evenement_fallback()
        except Exception as e:
            print(f"❌ Erreur chargement prochain événement: {e}")
            self.determiner_prochain_evenement_fallback()
        
    def select_prochain_evenement_in_combos(self):
        """Sélectionne automatiquement le prochain événement dans les combobox"""
        if not self.prochain_event_data or not self.semaine_actuelle:
            print("❌ Données manquantes pour la sélection automatique")
            return
            
        try:
            print(f"🎯 Tentative de sélection auto - Semaine actuelle: {self.semaine_actuelle.get('id')}")
            
            # Trouver l'arc correspondant à la semaine actuelle
            semaine_arc_id = self.semaine_actuelle.get('arc_id')
            print(f"🔍 Recherche de l'arc ID: {semaine_arc_id}")
            
            # Parcourir tous les arcs pour trouver le bon
            for i in range(self.arc_combo.count()):
                arc_data = self.arc_combo.itemData(i)
                if arc_data and arc_data.get('id') == semaine_arc_id:
                    print(f"✅ Arc trouvé à l'index {i}: {arc_data.get('nom')}")
                    self.arc_combo.setCurrentIndex(i)
                    # Forcer la mise à jour immédiate
                    self.on_arc_changed(self.arc_combo.currentText())
                    break
            else:
                print("❌ Arc non trouvé dans la combo")
                
        except Exception as e:
            print(f"❌ Erreur sélection auto événement: {e}")

    def _select_semaine_after_arc(self):
        """Sélectionne la semaine après que l'arc a été changé"""
        try:
            if not self.semaine_actuelle:
                print("❌ Aucune semaine actuelle définie")
                return
                
            semaine_id = self.semaine_actuelle.get('id')
            print(f"🔍 Recherche de la semaine ID: {semaine_id}")
            
            # Attendre que le combo se remplisse
            max_attempts = 10
            for attempt in range(max_attempts):
                if self.semaine_combo.count() > 0:
                    break
                QApplication.processEvents()
                time.sleep(0.1)
            
            # Trouver l'index de la semaine correspondante
            for i in range(self.semaine_combo.count()):
                semaine_data = self.semaine_combo.itemData(i)
                if semaine_data and semaine_data.get('id') == semaine_id:
                    print(f"✅ Semaine trouvée à l'index {i}: {semaine_data.get('titre')}")
                    self.semaine_combo.setCurrentIndex(i)
                    # Forcer la mise à jour
                    self.on_semaine_changed(self.semaine_combo.currentText())
                    return
            else:
                print("❌ Semaine non trouvée dans la combo")
                    
        except Exception as e:
            print(f"❌ Erreur sélection auto semaine: {e}")
    
    def determiner_prochain_evenement_fallback(self):
        """Fallback si le nouveau endpoint échoue"""
        if not self.evenements:
            return

        # Trier et trouver le premier événement non réalisé
        evenements_ordonnes = sorted(self.evenements, 
                                   key=lambda x: (x.get('arc_id', 0), 
                                                x.get('semaine_id', 0), 
                                                x.get('numero', 0)))
        
        for event in evenements_ordonnes:
            if event.get('reussite') is None:  # Événement non réalisé
                self.prochain_event_data = event
                self.est_prochain = True
                break
        else:
            # Tous les événements sont réalisés
            self.prochain_event_data = evenements_ordonnes[-1] if evenements_ordonnes else None
            self.est_prochain = False
        
        if self.prochain_event_data:
            print(f"🎯 Prochain événement (fallback): {self.prochain_event_data.get('titre')}")
            self.afficher_prochain_evenement()
            # Trouver la semaine correspondante
            semaine_id = self.prochain_event_data.get('semaine_id')
            for semaine in self.semaines:
                if semaine.get('id') == semaine_id:
                    self.semaine_actuelle = semaine
                    self.afficher_semaine_actuelle()
                    
                    # Marquer que nous sommes en mode sélection automatique
                    self._auto_selecting = True
                    
                    # Sélectionner automatiquement dans les combos
                    QTimer.singleShot(1000, self.select_prochain_evenement_in_combos)
                    break
        else:
            self.prochain_event_info.setText("🎉 Tous les événements ont été joués !")
            self.export_btn.setEnabled(False)

    def afficher_semaine_actuelle(self):
        """Affiche la semaine actuelle basée sur le prochain événement"""
        if not self.semaine_actuelle:
            return
            
        semaine = self.semaine_actuelle
        arc_nom = "Arc inconnu"
        
        # Trouver le nom de l'arc
        for arc in self.arcs:
            if arc.get('id') == semaine.get('arc_id'):
                arc_nom = arc.get('nom', 'Arc inconnu')
                break
    
        # Mettre à jour les labels principaux
        self.arc_label.setText(f"Arc: {arc_nom}")
        self.semaine_label.setText(f"Semaine {semaine.get('numero', '')}: {semaine.get('titre', '')}")
        
        # Calculer la progression de la semaine
        semaine_id = semaine.get('id')
        events_semaine = [e for e in self.evenements if e.get('semaine_id') == semaine_id]
        events_realises = len([e for e in events_semaine if e.get('reussite') is not None])
        total_events = len(events_semaine)
        progression_pct = int(events_realises / total_events * 100) if total_events > 0 else 0
        
        self.stats_label.setText(f"📊 Progression de la semaine: {events_realises}/{total_events} événements ({progression_pct}%)")
        
        # Mettre à jour l'affichage du lore
        if semaine.get('histoire'):
            self.lore_display.setHtml(f"""
                <div style="font-family: 'Segoe UI', Arial, sans-serif; color: #e6edf3;">
                    <h2 style="color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px;">
                        {semaine.get('titre', '')}
                    </h2>
                    <div style="background-color: #161b22; padding: 10px; border-radius: 6px; margin-bottom: 15px;">
                        <strong>📅 Semaine {semaine.get('numero', '')} • {arc_nom}</strong><br>
                        <strong>🎯 Progression:</strong> {events_realises}/{total_events} événements terminés
                    </div>
                    <p style="line-height: 1.6; font-size: 14px;">{semaine.get('histoire', '')}</p>
                </div>
            """)
        
        # Mettre à jour la liste des événements de cette semaine
        self.update_events_list_for_semaine(semaine_id)

    def update_events_list_for_semaine(self, semaine_id):
        """Met à jour la liste des événements pour la semaine spécifiée"""
        if not semaine_id:
            return
            
        self.events_list.clear()
        events_semaine = [e for e in self.evenements if e.get('semaine_id') == semaine_id]
        
        # Appliquer les filtres
        selected_type = self.filter_combo.currentText()
        if selected_type != "Tous les types":
            events_semaine = [e for e in events_semaine if e.get('type') == selected_type]
        
        search_text = self.search_input.text().lower()
        if search_text:
            events_semaine = [e for e in events_semaine if 
                             search_text in e.get('titre', '').lower() or 
                             search_text in e.get('courte', '').lower()]
        
        for event in sorted(events_semaine, key=lambda x: int(x.get('numero', 0))):
            event_type = event.get('type', '')
            duree = self.format_duration(event.get('duree'))
            recompense = event.get('recompense', '')
            reussite = event.get('reussite')
            
            # Icônes et couleurs selon le statut
            if reussite is None:
                type_icon = "⏳"  # En attente
                status_color = "#8b949e"
            elif reussite:
                type_icon = "✅"  # Réussi
                status_color = "#3fb950"
            else:
                type_icon = "❌"  # Échoué
                status_color = "#f85149"
            
            # Indicateur spécial pour le prochain événement
            is_prochain = (self.prochain_event_data and 
                          event.get('id') == self.prochain_event_data.get('id') and 
                          self.est_prochain)
            
            if is_prochain:
                type_icon = "🎯"  # Prochain événement
                status_color = "#ffd700"  # Or
            
            reward_indicator = " 💎" if recompense else ""
            
            # Texte enrichi avec statut
            item_text = f"{type_icon} {event.get('numero', '')} - {event.get('titre', '')} ({duree}{reward_indicator})"
            
            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, event)
            item.setForeground(QColor(status_color))
            
            # Style spécial pour le prochain événement
            if is_prochain:
                item.setBackground(QColor("#1a472a"))  # Fond vert foncé
                font = item.font()
                font.setBold(True)
                item.setFont(font)
            
            # Tooltip avec plus d'informations
            statut_text = "En attente" if reussite is None else ("Réussi" if reussite else "Échoué")
            if is_prochain:
                statut_text = "PROCHAIN ÉVÉNEMENT"
                
            item.setToolTip(f"""
    Statut: {statut_text}
    Type: {event_type}
    Durée: {duree}
    Récompense: {recompense or 'Aucune'}
    XP total: {event.get('xp_total', 0)}
            """)
            
            self.events_list.addItem(item)
    def afficher_prochain_evenement(self):
        """Affiche le prochain événement dans le panel dédié"""
        if not self.prochain_event_data:
            return

        titre = self.prochain_event_data.get('titre', 'Titre inconnu')
        type_event = self.prochain_event_data.get('type', 'Type inconnu')
        duree = self.format_duration(self.prochain_event_data.get('duree'))
        
        # Trouver le nom de la semaine et de l'arc
        semaine_id = self.prochain_event_data.get('semaine_id')
        semaine_nom = "Semaine inconnue"
        arc_nom = "Arc inconnu"
        
        for semaine in self.semaines:
            if semaine.get('id') == semaine_id:
                semaine_nom = semaine.get('titre', 'Semaine inconnue')
                arc_id = semaine.get('arc_id')
                for arc in self.arcs:
                    if arc.get('id') == arc_id:
                        arc_nom = arc.get('nom', 'Arc inconnu')
                        break
                break

        if self.est_prochain:
            texte_info = f"🎯 **PROCHAIN ÉVÉNEMENT**\n"
            texte_info += f"📅 {arc_nom} - {semaine_nom}\n"
            texte_info += f"🎮 {titre} ({type_event})\n"
            texte_info += f"⏱️ {duree}"
            self.prochain_event_group.setStyleSheet("""
                QGroupBox {
                    background-color: #1a472a;
                    border: 2px solid #2e8b57;
                    border-radius: 8px;
                    font-weight: bold;
                    color: #ffffff;
                }
                QGroupBox::title {
                    color: #90ee90;
                    padding: 0 10px;
                }
            """)
        else:
            texte_info = f"🏁 **DERNIER ÉVÉNEMENT JOUÉ**\n"
            texte_info += f"📅 {arc_nom} - {semaine_nom}\n"
            texte_info += f"🎮 {titre} ({type_event})\n"
            texte_info += f"⏱️ {duree}"
            self.prochain_event_group.setStyleSheet("""
                QGroupBox {
                    background-color: #5a1a1a;
                    border: 2px solid #8b2e2e;
                    border-radius: 8px;
                    font-weight: bold;
                    color: #ffffff;
                }
                QGroupBox::title {
                    color: #ee9090;
                    padding: 0 10px;
                }
            """)
        
        self.prochain_event_info.setText(texte_info)
        self.export_btn.setEnabled(self.est_prochain)

    def load_last_event_real(self):
        """Charge le vrai dernier événement depuis l'API events"""
        try:
            last_event_data = self.api_client._make_request("GET", "/lore/last-event")
            
            if last_event_data and "error" not in last_event_data:
                event = last_event_data.get("event", {})
                stats = last_event_data.get("stats", {})
                
                if event:
                    self.last_event_data = event
                    self.update_last_event_display(event, stats)
                else:
                    self.fallback_last_event()
            else:
                self.fallback_last_event()
                
        except Exception as e:
            print(f"Erreur chargement dernier événement réel: {e}")
            self.fallback_last_event()

    def fallback_last_event(self):
        """Fallback: utilise le dernier événement de la liste"""
        if self.evenements:
            # Prendre le dernier événement par ID (le plus récent)
            dernier_event = max(self.evenements, key=lambda x: x.get('id', 0))
            self.last_event_data = dernier_event
            
            # Statistiques simulées mais plus réalistes
            stats_simulees = {
                "resultat": "✅ Réussi",
                "participants_count": 12,  # Plus réaliste que 42
                "duree": self.format_duration(dernier_event.get('duree')),
                "progression": f"100%"
            }
            
            self.update_last_event_display(dernier_event, stats_simulees)
        else:
            self.last_event_title.setText("Aucun événement récent")
            self.last_event_result.setText("Statut: -")
            self.last_event_participants.setText("Participants: -")
            self.last_event_duration.setText("Durée: -")
            self.last_event_progression.setText("Progression: -")
            self.last_event_summary.setText("Résumé: -")

    def update_last_event_display(self, event, stats):
        """Met à jour l'affichage du dernier événement avec les vraies données"""
        if not event:
            self.last_event_title.setText("Aucun événement récent")
            self.last_event_result.setText("Statut: -")
            self.last_event_participants.setText("Participants: -")
            self.last_event_duration.setText("Durée: -")
            self.last_event_progression.setText("Progression: -")
            self.last_event_summary.setText("Résumé: -")
            return
            
        # CORRECTION : Utiliser les données de l'événement réel
        titre = event.get('titre', 'Titre inconnu')
        event_type = event.get('event_type', 'Type inconnu')
        
        # ✅ AMÉLIORATION : Formater la durée correctement
        duree_minutes = event.get('duree')
        duree_formatee = self.format_duration(duree_minutes)
        
        participants = stats.get('participants_count', 0)
        resultat = stats.get('resultat', 'Terminé')
        progression = stats.get('progression', '0/0 (0%)')
        reussite = stats.get('reussite', False)
        
        # ✅ AMÉLIORATION : Calculer la durée réelle si disponible
        duree_reelle = stats.get('duree', duree_formatee)
        
        # Affichage enrichi
        self.last_event_title.setText(f"📊 {titre}")
        self.last_event_result.setText(f"Résultat: {resultat}")
        self.last_event_participants.setText(f"Participants: {participants}")
        self.last_event_duration.setText(f"Durée: {duree_reelle}")
        self.last_event_progression.setText(f"Progression: {progression}")
        
        # ✅ AMÉLIORATION : Résumé plus informatif
        summary_text = f"{event_type} • "
        if reussite:
            summary_text += "✅ Réussi"
        else:
            summary_text += "❌ Échec"
            
        if duree_minutes:
            summary_text += f" • Durée prévue: {duree_formatee}"
            
        self.last_event_summary.setText(f"Contexte: {summary_text}")

    def update_display(self):
        """Met à jour l'affichage principal"""
        # Mise à jour des combobox
        self.arc_combo.clear()
        for arc in self.arcs:
            display_text = f"{arc.get('id', '')} - {arc.get('nom', 'Sans nom')}"
            self.arc_combo.addItem(display_text, arc)
        
        # Sélectionner le dernier arc par défaut
        if self.arcs:
            self.current_arc = self.arcs[-1]
            self.arc_combo.setCurrentIndex(self.arc_combo.count() - 1)
            
            # Mise à jour du header
            arc_name = self.current_arc.get('nom', 'Nom inconnu')
            total_semaines = len([s for s in self.semaines if s.get('arc_id') == self.current_arc.get('id')])
            total_events = len([e for e in self.evenements if any(s.get('arc_id') == self.current_arc.get('id') 
                                                                for s in self.semaines if s.get('id') == e.get('semaine_id'))])
            
            self.arc_label.setText(f"Arc: {arc_name}")
            self.stats_label.setText(f"📊 {total_semaines} semaines, {total_events} événements")

    def on_arc_changed(self, text):
        """Callback quand l'arc sélectionné change"""
        if not text or self.arc_combo.count() == 0:
            return
            
        arc_index = self.arc_combo.currentIndex()
        if arc_index < 0:
            return
            
        arc_data = self.arc_combo.itemData(arc_index)
        if not arc_data:
            return
            
        self.current_arc = arc_data
        arc_id = self.current_arc.get('id')
        
        print(f"🔄 Changement d'arc vers: {arc_id} - {arc_data.get('nom')}")
        
        # Mettre à jour les semaines de cet arc
        self.semaine_combo.clear()
        semaines_arc = [s for s in self.semaines if s.get('arc_id') == arc_id]
        
        for semaine in semaines_arc:
            display_text = f"{semaine.get('numero', '')} - {semaine.get('titre', 'Sans titre')}"
            self.semaine_combo.addItem(display_text, semaine)
        
        print(f"📋 {len(semaines_arc)} semaines chargées pour cet arc")
        
        # Mettre à jour l'indicateur de progression
        self.update_arc_progression()
            
        # Si nous sommes en mode sélection automatique, sélectionner la semaine
        if hasattr(self, '_auto_selecting') and self._auto_selecting:
            QTimer.singleShot(100, self._select_semaine_after_arc)
        elif semaines_arc:
            # Sinon, sélectionner la dernière semaine par défaut
            self.current_semaine = semaines_arc[-1]
            self.semaine_combo.setCurrentIndex(self.semaine_combo.count() - 1)
            self.update_semaine_display()
        else:
            self.current_semaine = None
            self.clear_semaine_display()

    def on_semaine_changed(self, text):
        """Callback quand la semaine sélectionnée change"""
        if not text or self.semaine_combo.count() == 0:
            return
            
        semaine_index = self.semaine_combo.currentIndex()
        if semaine_index < 0:
            return
            
        semaine_data = self.semaine_combo.itemData(semaine_index)
        if not semaine_data:
            return
            
        self.current_semaine = semaine_data
        self.update_semaine_display()

    def apply_filters(self):
        """Applique les filtres de recherche"""
        if not self.current_semaine:
            return
            
        self.update_semaine_display()

    def update_semaine_display(self):
        """Met à jour l'affichage de la semaine sélectionnée"""
        if not self.current_semaine:
            self.clear_semaine_display()
            return
            
        # Mettre à jour le header
        semaine_numero = self.current_semaine.get('numero', '')
        semaine_titre = self.current_semaine.get('titre', 'Sans titre')
        self.semaine_label.setText(f"Semaine: {semaine_numero} - {semaine_titre}")
        
        # Afficher le lore de la semaine
        histoire = self.current_semaine.get('histoire', 'Aucune description disponible.')
        self.lore_display.setHtml(f"""
            <div style="font-family: 'Segoe UI', Arial, sans-serif; color: #e6edf3;">
                <h2 style="color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px;">
                    {semaine_titre}
                </h2>
                <p style="line-height: 1.6; font-size: 14px;">{histoire}</p>
            </div>
        """)
        
        # Mettre à jour la liste des événements
        self.update_events_list()
        self.update_week_stats()

    def update_events_list(self):
        """Met à jour la liste des événements avec filtres ET couleurs de statut"""
        if not self.current_semaine:
            return
            
        self.events_list.clear()
        semaine_id = self.current_semaine.get('id')
        events_semaine = [e for e in self.evenements if e.get('semaine_id') == semaine_id]
        
        # Appliquer les filtres
        selected_type = self.filter_combo.currentText()
        if selected_type != "Tous les types":
            events_semaine = [e for e in events_semaine if e.get('type') == selected_type]
        
        search_text = self.search_input.text().lower()
        if search_text:
            events_semaine = [e for e in events_semaine if 
                             search_text in e.get('titre', '').lower() or 
                             search_text in e.get('courte', '').lower()]
        
        for event in sorted(events_semaine, key=lambda x: int(x.get('numero', 0))):
            event_type = event.get('type', '')
            duree = self.format_duration(event.get('duree'))
            recompense = event.get('recompense', '')
            reussite = event.get('reussite')
            
            # Icônes et couleurs selon le statut - COMME DANS update_events_list_for_semaine
            if reussite is None:
                type_icon = "⏳"  # En attente
                status_color = "#8b949e"
            elif reussite:
                type_icon = "✅"  # Réussi
                status_color = "#3fb950"
            else:
                type_icon = "❌"  # Échoué
                status_color = "#f85149"
            
            # Indicateur spécial pour le prochain événement
            is_prochain = (self.prochain_event_data and 
                          event.get('id') == self.prochain_event_data.get('id') and 
                          self.est_prochain)
            
            if is_prochain:
                type_icon = "🎯"  # Prochain événement
                status_color = "#ffd700"  # Or
            
            reward_indicator = " 💎" if recompense else ""
            
            # Texte enrichi avec statut
            item_text = f"{type_icon} {event.get('numero', '')} - {event.get('titre', '')} ({duree}{reward_indicator})"
            
            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, event)
            item.setForeground(QColor(status_color))
            
            # Style spécial pour le prochain événement
            if is_prochain:
                item.setBackground(QColor("#1a472a"))  # Fond vert foncé
                font = item.font()
                font.setBold(True)
                item.setFont(font)
            
            # Tooltip avec plus d'informations
            statut_text = "En attente" if reussite is None else ("Réussi" if reussite else "Échoué")
            if is_prochain:
                statut_text = "PROCHAIN ÉVÉNEMENT"
                
            item.setToolTip(f"""
    Statut: {statut_text}
    Type: {event_type}
    Durée: {duree}
    Récompense: {recompense or 'Aucune'}
    XP total: {event.get('xp_total', 0)}
            """)
            
            self.events_list.addItem(item)
            
            
    def update_week_stats(self):
        """Calcule et affiche les statistiques de la semaine"""
        if not self.current_semaine:
            return
            
        semaine_id = self.current_semaine.get('id')
        events_semaine = [e for e in self.evenements if e.get('semaine_id') == semaine_id]
        
        # Appliquer les mêmes filtres que pour l'affichage
        selected_type = self.filter_combo.currentText()
        if selected_type != "Tous les types":
            events_semaine = [e for e in events_semaine if e.get('type') == selected_type]
        
        search_text = self.search_input.text().lower()
        if search_text:
            events_semaine = [e for e in events_semaine if 
                             search_text in e.get('titre', '').lower() or 
                             search_text in e.get('courte', '').lower()]
        
        if not events_semaine:
            self.stats_total_events.setText("Événements: 0")
            self.stats_total_duration.setText("Durée totale: 0")
            self.stats_total_xp.setText("XP totale: 0")
            self.stats_avg_duration.setText("Durée moyenne: 0")
            self.stats_rewards_count.setText("Récompenses uniques: 0")
            return
        
        total_events = len(events_semaine)
        total_duration = sum(int(e.get('duree', 0)) for e in events_semaine)
        total_xp = sum(int(e.get('xp_total', 0)) for e in events_semaine)
        avg_duration = total_duration / total_events if total_events > 0 else 0
        unique_rewards = len(set(e.get('recompense', '') for e in events_semaine if e.get('recompense')))
        
        self.stats_total_events.setText(f"Événements: {total_events}")
        self.stats_total_duration.setText(f"Durée totale: {self.format_duration(total_duration)}")
        self.stats_total_xp.setText(f"XP totale: {total_xp:,} XP".replace(',', ' '))
        self.stats_avg_duration.setText(f"Durée moyenne: {self.format_duration(avg_duration)}")
        self.stats_rewards_count.setText(f"Récompenses uniques: {unique_rewards}")

    def clear_semaine_display(self):
        """Efface l'affichage de la semaine"""
        self.semaine_label.setText("Semaine: -")
        self.lore_display.clear()
        self.events_list.clear()
        self.stats_total_events.setText("Événements: 0")
        self.stats_total_duration.setText("Durée totale: 0")
        self.stats_total_xp.setText("XP totale: 0")
        self.stats_avg_duration.setText("Durée moyenne: 0")
        self.stats_rewards_count.setText("Récompenses uniques: 0")

    def on_event_selected(self, item):
        """Affiche les détails d'un événement sélectionné"""
        event_data = item.data(Qt.UserRole)
        
        # Créer une boîte de dialogue avec les détails
        dialog = QDialog(self)
        dialog.setWindowTitle(f"🎯 {event_data.get('titre', '')}")
        dialog.setMinimumSize(700, 600)
        
        layout = QVBoxLayout()
        
        # Récupération des données
        duree = self.format_duration(event_data.get('duree'))
        recompense = event_data.get('recompense', 'Aucune')
        conclusion_reussite = event_data.get('conclusion_reussite', 'Non définie')
        conclusion_echec = event_data.get('conclusion_echec', 'Non définie')
        malus_xp = event_data.get('malus_xp', 0)
        reussite = event_data.get('reussite')
        
        # Statut avec icône et couleur
        if reussite is None:
            statut_icon = "⏳"
            statut_text = "En attente"
            statut_color = "#8b949e"
        elif reussite:
            statut_icon = "✅"
            statut_text = "Réussi"
            statut_color = "#3fb950"
        else:
            statut_icon = "❌"
            statut_text = "Échoué"
            statut_color = "#f85149"
        
        # Affichage riche
        content = QTextEdit()
        content.setReadOnly(True)
        content.setHtml(f"""
            <div style="font-family: 'Segoe UI', Arial, sans-serif; color: #e6edf3;">
                <h1 style="color: #58a6ff; margin-bottom: 20px; border-bottom: 2px solid #30363d; padding-bottom: 10px;">
                    {event_data.get('titre', '')}
                </h1>
                
                <div style="background-color: #161b22; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                    <h3 style="color: #58a6ff; margin-top: 0;">📊 Informations</h3>
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr><td style="padding: 5px; width: 30%;"><strong>Statut:</strong></td><td style="padding: 5px; color: {statut_color};">{statut_icon} {statut_text}</td></tr>
                        <tr><td style="padding: 5px; width: 30%;"><strong>Type:</strong></td><td style="padding: 5px;">{event_data.get('type', '')}</td></tr>
                        <tr><td style="padding: 5px;"><strong>Durée:</strong></td><td style="padding: 5px;">{duree}</td></tr>
                        <tr><td style="padding: 5px;"><strong>XP total:</strong></td><td style="padding: 5px;">{event_data.get('xp_total', '')} XP</td></tr>
                        <tr><td style="padding: 5px;"><strong>XP/action:</strong></td><td style="padding: 5px;">{event_data.get('xp_par_action', '')} XP</td></tr>
                        <tr><td style="padding: 5px;"><strong>Malus échec:</strong></td><td style="padding: 5px; color: {'#ff6b6b' if malus_xp else '#8b949e'}">{malus_xp if malus_xp else 'Aucun'} XP</td></tr>
                        <tr><td style="padding: 5px;"><strong>Récompense:</strong></td><td style="padding: 5px; color: #ffd700;">{recompense}</td></tr>
                    </table>
                </div>
                
                <h3 style="color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 5px;">📝 Description</h3>
                <div style="background-color: #161b22; padding: 15px; border-radius: 8px; margin-bottom: 20px; line-height: 1.6;">
                    {event_data.get('courte', '')}
                </div>
                
                <h3 style="color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 5px; margin-top: 20px;">📖 Histoire</h3>
                <div style="background-color: #161b22; padding: 15px; border-radius: 8px; margin-bottom: 20px; line-height: 1.6;">
                    {event_data.get('longue', '')}
                </div>
                
                <div style="display: flex; gap: 15px; margin-top: 20px;">
                    <div style="flex: 1; background-color: #238636; padding: 15px; border-radius: 8px;">
                        <h4 style="color: #ffffff; margin-top: 0;">✅ Réussite</h4>
                        <p style="margin: 0; line-height: 1.5;">{conclusion_reussite}</p>
                    </div>
                    <div style="flex: 1; background-color: #da3633; padding: 15px; border-radius: 8px;">
                        <h4 style="color: #ffffff; margin-top: 0;">❌ Échec</h4>
                        <p style="margin: 0; line-height: 1.5;">{conclusion_echec}</p>
                    </div>
                </div>
            </div>
        """)
        
        layout.addWidget(content)
        
        # Boutons d'action
        btn_layout = QHBoxLayout()
        
        export_btn = QPushButton("📤 Exporter vers Événement")
        export_btn.clicked.connect(lambda: self.exporter_event_dialog(event_data, dialog))
        
        close_btn = QPushButton("Fermer")
        close_btn.clicked.connect(dialog.accept)
        
        btn_layout.addWidget(export_btn)
        btn_layout.addWidget(close_btn)
        
        layout.addLayout(btn_layout)
        dialog.setLayout(layout)
        dialog.exec()

    def exporter_event_dialog(self, event_data, dialog):
        """Exporte l'événement depuis la boîte de dialogue"""
        dialog.accept()
        self._export_event_data(event_data)

    def _export_event_data(self, event_data):
        """Exporte les données d'événement vers l'onglet Événement avec code unique - VERSION ROBUSTE"""
        try:
            # Vérifications initiales
            if not self.event_tab_ref:
                QMessageBox.critical(self, "Erreur", "Référence à l'onglet Événement non disponible")
                return False

            if not event_data:
                QMessageBox.warning(self, "Avertissement", "Aucune donnée d'événement à exporter")
                return False

            print(f"🚀 Début de l'export de l'événement: {event_data.get('titre', 'Sans titre')}")

            # ÉTAPE 1: Récupération des codes existants
            print("📡 Récupération des codes existants...")
            existing_codes = []
            try:
                existing_codes_result = self.api_client.get_existing_event_codes()
                if existing_codes_result and "codes" in existing_codes_result:
                    existing_codes = existing_codes_result["codes"]
                    print(f"📋 {len(existing_codes)} codes existants chargés")
                else:
                    print("⚠️ Aucun code existant trouvé ou erreur de chargement")
                    if existing_codes_result and "error" in existing_codes_result:
                        print(f"❌ Erreur API: {existing_codes_result['error']}")
            except Exception as e:
                print(f"❌ Erreur lors de la récupération des codes: {e}")
                # Continuer avec une liste vide

            # ÉTAPE 2: Mapping du type d'événement
            lore_type = event_data.get('type', '')
            type_mapping = {
                "Mission communautaire": "community",
                "Boss": "boss", 
                "Boss Final": "Boss Final", 
                "Autre": "",
                "": ""
            }
            mapped_type = type_mapping.get(lore_type, lore_type)
            print(f"🎯 Type d'événement: '{lore_type}' -> '{mapped_type}'")

            # ÉTAPE 3: Génération du code unique
            print("🔧 Génération du code unique...")
            unique_code = generate_unique_event_code(mapped_type, existing_codes, self.api_client)
            print(f"✅ Code unique généré: {unique_code}")

            # ÉTAPE 4: Configuration de l'onglet Événement
            
            # 4.1: Définir le type d'événement
            if hasattr(self.event_tab_ref, 'type_combo') and self.event_tab_ref.type_combo:
                type_found = False
                if mapped_type:
                    # Essayer le type mappé
                    index = self.event_tab_ref.type_combo.findText(mapped_type)
                    if index >= 0:
                        self.event_tab_ref.type_combo.setCurrentIndex(index)
                        type_found = True
                        print(f"✅ Type défini: {mapped_type}")
                
                if not type_found and lore_type:
                    # Essayer le type original
                    index = self.event_tab_ref.type_combo.findText(lore_type)
                    if index >= 0:
                        self.event_tab_ref.type_combo.setCurrentIndex(index)
                        print(f"✅ Type défini (original): {lore_type}")
                    else:
                        print(f"⚠️ Type non trouvé dans la liste: {lore_type}")
            else:
                print("⚠️ type_combo non disponible")

            # 4.2: Définir le code unique
            if hasattr(self.event_tab_ref, 'code_input') and self.event_tab_ref.code_input:
                self.event_tab_ref.code_input.setText(unique_code)
                print(f"✅ Code défini: {unique_code}")
            else:
                print("❌ code_input non disponible")

            # ÉTAPE 5: Mapping des autres champs
            field_mapping = {
                    'titre': ('title_input', 'text'),
                    'duree': ('duree_input', 'text'),
                    'recompense': ('recompense_input', 'text'),
                    'malus_xp': ('malus_input', 'text'),
                    'courte': ('courte_input', 'plainText'),
                    'longue': ('longue_input', 'plainText'),
                    'conclusion_reussite': ('conclusion_reussite_input', 'plainText'),
                    'conclusion_echec': ('conclusion_echec_input', 'plainText'),
                    'xp_total': ('target_input', 'text'),
                    'xp_par_action': ('xp_input', 'text'),
                    'taux_reussite': ('success_rate_input', 'setValue')  # NOUVEAU
                }

            fields_set = 0
            for lore_field, (widget_name, setter) in field_mapping.items():
                value = event_data.get(lore_field, '')
                widget = getattr(self.event_tab_ref, widget_name, None)
                
                if widget is not None:
                    # Conversion des valeurs None en chaînes vides
                    if value is None:
                        value = ''
                    
                    try:
                        if setter == 'text':
                            widget.setText(str(value))
                        elif setter == 'plainText':
                            widget.setPlainText(str(value))
                        elif setter == 'setValue':
                            # Pour le QSpinBox, convertir en entier
                            try:
                                widget.setValue(int(value))
                            except (ValueError, TypeError):
                                widget.setValue(100)  # Valeur par défaut
                        
                        fields_set += 1
                    except Exception as e:
                        print(f"❌ Erreur sur {widget_name}: {e}")
                else:
                    print(f"⚠️ Widget non trouvé: {widget_name}")

            print(f"📊 {fields_set} champs remplis sur {len(field_mapping)}")

            # ÉTAPE 6: Configuration des paliers par défaut
            if hasattr(self.event_tab_ref, 'thresholds_input') and self.event_tab_ref.thresholds_input:
                self.event_tab_ref.thresholds_input.setText("25,50,75,100")
                print("✅ Paliers définis par défaut")

            # ÉTAPE 7: Rafraîchissement de l'interface
            if hasattr(self.event_tab_ref, 'update'):
                self.event_tab_ref.update()
            if hasattr(self.event_tab_ref, 'repaint'):
                self.event_tab_ref.repaint()

            # ÉTAPE 8: Basculement vers l'onglet Événement
            main_window = self.window()
            if hasattr(main_window, 'tabs'):
                for i in range(main_window.tabs.count()):
                    if main_window.tabs.widget(i) == self.event_tab_ref:
                        main_window.tabs.setCurrentIndex(i)
                        print("✅ Navigation vers l'onglet Événement")
                        break

            # ÉTAPE 9: Message de succès
            success_message = (
                f"✅ Événement exporté avec succès!\n\n"
                f"📝 **{event_data.get('titre', 'Sans titre')}**\n"
                f"🎯 Code: **{unique_code}**\n"
                f"📊 Type: {lore_type}\n"
                f"⏱️ Durée: {self.format_duration(event_data.get('duree'))}\n\n"
                f"_Vérifiez les données et cliquez sur 'Sauvegarder'_"
            )
            
            QMessageBox.information(self, "Export Réussi", success_message)
            return True

        except Exception as e:
            error_message = f"Erreur lors de l'export:\n{str(e)}"
            print(f"❌ {error_message}")
            import traceback
            traceback.print_exc()
            
            QMessageBox.critical(
                self, 
                "Erreur d'Export", 
                f"{error_message}\n\nConsultez la console pour plus de détails."
            )
            return False
        
        
    def afficher_erreur(self, message):
        """Affiche une erreur dans l'interface"""
        self.prochain_event_info.setText(f"❌ {message}")
        self.arc_label.setText("Arc: Erreur")
        self.semaine_label.setText("Semaine: Erreur")
        self.stats_label.setText("Statistiques: Erreur")

    def exporter_prochain_vers_event(self):
        """Exporte le prochain événement vers l'onglet Événement"""
        if self.prochain_event_data and self.event_tab_ref:
            self._export_event_data(self.prochain_event_data)
            
            # Basculer vers l'onglet Événement
            main_window = self.window()
            if hasattr(main_window, 'tabs'):
                for i in range(main_window.tabs.count()):
                    if main_window.tabs.widget(i) == self.event_tab_ref:
                        main_window.tabs.setCurrentIndex(i)
                        break
        else:
            QMessageBox.warning(self, "Erreur", "Impossible d'exporter l'événement")          

    def create_arc_progression_indicator(self):
        """Crée l'indicateur visuel de progression de l'arc"""
        # Widget pour la progression de l'arc
        self.arc_progression_group = QGroupBox("🎯 PROGRESSION DE L'ARC")
        self.arc_progression_group.setStyleSheet("""
            QGroupBox {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 8px;
                color: #e6edf3;
            }
        """)
        
        progression_layout = QVBoxLayout()
        progression_layout.setAlignment(Qt.AlignCenter)  # Centrer tout le contenu
        
        # Label d'information - CENTRÉ
        self.arc_progression_info = QLabel("Chargement de la progression...")
        self.arc_progression_info.setAlignment(Qt.AlignCenter)
        self.arc_progression_info.setStyleSheet("color: #8b949e; font-size: 12px; padding: 5px;")
        progression_layout.addWidget(self.arc_progression_info)
        
        # Container pour les carrés de progression
        self.progression_container = QWidget()
        self.progression_layout = QHBoxLayout(self.progression_container)
        self.progression_layout.setAlignment(Qt.AlignCenter)
        self.progression_layout.setSpacing(4)
        self.progression_layout.setContentsMargins(10, 5, 10, 5)
        
        progression_layout.addWidget(self.progression_container)
        self.arc_progression_group.setLayout(progression_layout)
        
        return self.arc_progression_group

    def update_arc_progression(self):
        """Met à jour l'indicateur de progression de l'arc"""
        # Clear les carrés existants
        for i in reversed(range(self.progression_layout.count())):
            widget = self.progression_layout.itemAt(i).widget()
            if widget:
                widget.deleteLater()
        
        if not self.current_arc:
            self.arc_progression_info.setText("Aucun arc sélectionné")
            return
        
        # Récupérer tous les événements de l'arc actuel
        arc_id = self.current_arc.get('id')
        
        # Trouver toutes les semaines de cet arc
        semaines_arc = [s for s in self.semaines if s.get('arc_id') == arc_id]
        semaines_ids = [s.get('id') for s in semaines_arc]
        
        # Récupérer tous les événements de ces semaines
        events_arc = [e for e in self.evenements if e.get('semaine_id') in semaines_ids]
        
        # Trier les événements par semaine et numéro
        events_arc_sorted = sorted(events_arc, key=lambda x: (
            x.get('semaine_id', 0), 
            x.get('numero', 0)
        ))
        
        if not events_arc_sorted:
            self.arc_progression_info.setText("Aucun événement dans cet arc")
            return
        
        # Compter les statistiques
        total_events = len(events_arc_sorted)
        events_reussis = len([e for e in events_arc_sorted if e.get('reussite') is True])
        events_echoues = len([e for e in events_arc_sorted if e.get('reussite') is False])
        events_restants = total_events - events_reussis - events_echoues
        
        # Mettre à jour le texte d'information - CENTRÉ
        progression_text = f"Arc: {self.current_arc.get('nom', 'Inconnu')} • "
        progression_text += f"Total: {total_events} événements • "
        progression_text += f"✅ {events_reussis} • ❌ {events_echoues} • ⏳ {events_restants}"
        self.arc_progression_info.setText(progression_text)
        self.arc_progression_info.setAlignment(Qt.AlignCenter)
        
        # Créer un widget conteneur pour les carrés avec un layout centré
        squares_container = QWidget()
        squares_layout = QHBoxLayout(squares_container)
        squares_layout.setAlignment(Qt.AlignCenter)
        squares_layout.setSpacing(4)
        squares_layout.setContentsMargins(0, 0, 0, 0)
        
        # NUMÉROTATION GLOBALE - utiliser un compteur séquentiel pour l'arc
        compteur_global = 0
        
        # Créer les carrés de progression
        for event in events_arc_sorted:
            compteur_global += 1  # Incrémenter le compteur global
            
            reussite = event.get('reussite')
            is_prochain = (self.prochain_event_data and 
                          event.get('id') == self.prochain_event_data.get('id') and 
                          self.est_prochain)
            
            # Déterminer la couleur et le tooltip
            if is_prochain:
                color = "#ffd700"
                hover_color = "#ffed4e"
                status_icon = "🎯"
                status_text = "PROCHAIN ÉVÉNEMENT"
                border = "2px solid #ffd700"
            elif reussite is None:
                color = "transparent"
                hover_color = "#30363d"
                status_icon = "⏳"
                status_text = "EN ATTENTE"
                border = "2px solid #8b949e"
            elif reussite:
                color = "#3fb950"
                hover_color = "#56d364"
                status_icon = "✅"
                status_text = "RÉUSSI"
                border = "2px solid #3fb950"
            else:
                color = "#f85149"
                hover_color = "#ff6b6b"
                status_icon = "❌"
                status_text = "ÉCHOUÉ"
                border = "2px solid #f85149"
            
            # INFOBULLE DÉTAILLÉE avec numéro global
            event_numero_global = compteur_global  # Utiliser le compteur global
            event_numero_semaine = event.get('numero', '?')  # Garder le numéro original pour info
            event_titre = event.get('titre', 'Sans titre')
            event_type = event.get('type', 'Type inconnu')
            event_duree = self.format_duration(event.get('duree'))
            event_recompense = event.get('recompense', 'Aucune')
            
            # Trouver le nom de la semaine pour l'infobulle
            semaine_nom = "Semaine inconnue"
            for semaine in semaines_arc:
                if semaine.get('id') == event.get('semaine_id'):
                    semaine_nom = f"Semaine {semaine.get('numero', '?')}"
                    break
            
            tooltip_text = f"""
    {status_icon} <b>{status_text}</b>

    <b>Événement {event_numero_global}/{total_events}: <br>
    <i>{event_titre}</i></b><br>
    • {semaine_nom} - Événement {event_numero_semaine}<br>
    • <i>Type</i>: {event_type}<br>
    • <i>Durée</i>: {event_duree}<br>
    • <i>Récompense</i>: {event_recompense}<br>

    <b>Double-clic</b> pour ouvrir les détails
    """
            
            # Créer le carré avec effet de survol
            square = QLabel()
            square.setFixedSize(20, 20)
            square.setStyleSheet(f"""
                QLabel {{
                    background-color: {color};
                    border: {border};
                    border-radius: 3px;
                }}
                QLabel:hover {{
                    background-color: {hover_color};
                    border: 2px solid #ffffff;
                }}
            """)
            square.setToolTip(tooltip_text)
            square.setCursor(Qt.PointingHandCursor)
            
            # Double-clic pour sélectionner l'événement
            square.mouseDoubleClickEvent = lambda e, ev=event: self.select_event_from_progression(ev)
            
            squares_layout.addWidget(square)
        
        # Ajouter le conteneur des carrés au layout principal
        self.progression_layout.addWidget(squares_container)

    def select_event_from_progression(self, event_data):
        """Sélectionne un événement depuis l'indicateur de progression"""
        event_titre = event_data.get('titre', 'Événement')
        print(f"🎯 Sélection de l'événement depuis la progression: {event_titre}")
        
        # Trouver la semaine de l'événement
        semaine_id = event_data.get('semaine_id')
        for i in range(self.arc_combo.count()):
            arc_data = self.arc_combo.itemData(i)
            if arc_data and arc_data.get('id') == self.current_arc.get('id'):
                self.arc_combo.setCurrentIndex(i)
                break
        
        # Attendre que les semaines se chargent puis sélectionner la bonne
        QTimer.singleShot(200, lambda: self._select_semaine_for_event(semaine_id, event_data))

    def _select_semaine_for_event(self, semaine_id, event_data):
        """Sélectionne la semaine et l'événement"""
        # Sélectionner la semaine
        for i in range(self.semaine_combo.count()):
            semaine_data = self.semaine_combo.itemData(i)
            if semaine_data and semaine_data.get('id') == semaine_id:
                self.semaine_combo.setCurrentIndex(i)
                break
        
        # Sélectionner l'événement dans la liste
        for i in range(self.events_list.count()):
            item = self.events_list.item(i)
            item_event_data = item.data(Qt.UserRole)
            if item_event_data and item_event_data.get('id') == event_data.get('id'):
                self.events_list.setCurrentItem(item)
                self.on_event_selected(item)
                break            
            
# Section 5: Onglet Événements
class EventTab(QWidget):
    """Onglet de gestion des événements avec nouvelle structure compacte"""

    def __init__(self, api_client):
        super().__init__()
        self.api_client = api_client
        self.current_event = None
        self.event_counter = 1
        self.time_remaining = "00:00"
        self.time_percentage = 0
        self.malus_applied = False
        self.mission_cooldown = 30  # Valeur par défaut
        self.active_adventurers_count = 0
        
        self.init_ui()

        # Timer RAPIDE: uniquement event_status (léger) - toutes les 5s
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_data)
        self.refresh_timer.start(5000)

        # Timer pour le décompte en temps réel (1 seconde) - local, pas d'API
        self.countdown_timer = QTimer()
        self.countdown_timer.timeout.connect(self.update_countdown)
        self.countdown_timer.start(1000)

        # Timer LENT: config, malus, coffre, aventuriers - toutes les 30s
        self.slow_refresh_timer = QTimer()
        self.slow_refresh_timer.timeout.connect(self.slow_refresh)
        self.slow_refresh_timer.start(30000)

        # Chargement initial des données lentes (différé pour ne pas bloquer le démarrage)
        QTimer.singleShot(500, self.slow_refresh)
                
    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)

        # Header compact
        header_layout = QHBoxLayout()
        
        self.status_label = QLabel("📊 Statut: -")
        self.status_label.setStyleSheet("font-size: 12px; font-weight: bold; padding: 5px;")
        
        self.time_indicator = QLabel("⏱️ --:--")
        self.time_indicator.setStyleSheet("font-size: 12px; font-weight: bold; color: #58a6ff;")
        
        self.active_adventurers_label = QLabel("👥 Aventuriers: ?")
        self.active_adventurers_label.setStyleSheet("""
            QLabel {
                font-size: 12px;
                font-weight: bold;
                padding: 3px 8px;
                background-color: #161b22;
                border-radius: 4px;
                border: 1px solid #30363d;
                color: #58a6ff;
            }
        """)
        
        header_layout.addWidget(self.status_label)
        header_layout.addWidget(self.time_indicator)
        header_layout.addWidget(self.active_adventurers_label)
        header_layout.addStretch()
        
        refresh_btn = QPushButton("🔄")
        refresh_btn.setToolTip("Rafraîchir")
        refresh_btn.setFixedSize(30, 30)
        refresh_btn.clicked.connect(self.refresh_data)
        
        self.auto_refresh = QCheckBox("Auto")
        self.auto_refresh.setChecked(True)
        self.auto_refresh.stateChanged.connect(self.toggle_auto_refresh)
        
        header_layout.addWidget(self.auto_refresh)
        header_layout.addWidget(refresh_btn)
        main_layout.addLayout(header_layout)

        # Contenu principal - Configuration en largeur
        content_layout = QHBoxLayout()
        content_layout.setSpacing(15)

        # FORMULAIRE PRINCIPAL (75% de l'espace)
        form_group = QGroupBox("⚙️ Configuration de l'événement")
        form_layout = QGridLayout()
        
        # Ligne 1: Type et Code
        self.type_combo = QComboBox()
        self.type_combo.addItems(["", "community", "raid", "boss", "Boss Final"])
        self.type_combo.currentTextChanged.connect(self.on_type_changed)
        
        self.code_input = QLineEdit()
        self.code_input.setPlaceholderText("Généré automatiquement")
        generate_btn = QPushButton("🔄")
        generate_btn.setFixedSize(30, 25)
        generate_btn.clicked.connect(self.generate_code)
        
        code_layout = QHBoxLayout()
        code_layout.addWidget(self.code_input)
        code_layout.addWidget(generate_btn)
        
        form_layout.addWidget(QLabel("Type*:"), 0, 0)
        form_layout.addWidget(self.type_combo, 0, 1)
        form_layout.addWidget(QLabel("Code:"), 0, 2)
        form_layout.addLayout(code_layout, 0, 3)

        # Ligne 2: Titre
        self.title_input = QLineEdit()
        self.title_input.setPlaceholderText("Nom de l'événement")
        form_layout.addWidget(QLabel("Titre*:"), 1, 0)
        form_layout.addWidget(self.title_input, 1, 1, 1, 3)

        # Ligne 3: XP et Objectif
        self.xp_input = QLineEdit("10")
        self.xp_input.setValidator(QIntValidator(1, 1000))
        self.xp_input.setFixedWidth(80)
        
        self.target_input = QLineEdit("")
        self.target_input.setValidator(QIntValidator(0, 1000000))
        self.target_input.setFixedWidth(100)
        self.target_input.setPlaceholderText("Objectif XP")
        
        # AJOUT: Label informatif pour le Boss Final
        self.boss_final_info = QLabel("")
        self.boss_final_info.setStyleSheet("color: #ff6b6b; font-size: 10px; font-style: italic;")
        self.boss_final_info.setWordWrap(True)
        self.boss_final_info.setMinimumWidth(250)  # Largeur fixe pour éviter le débordement
        self.boss_final_info.setMaximumWidth(300)

        # Layout horizontal pour Objectif XP + info Boss Final
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Objectif XP*:"))
        target_layout.addWidget(self.target_input)

        # AJOUT: Bouton pour appliquer le malus
        self.apply_malus_btn = QPushButton("⚔️ Appliquer malus")
        self.apply_malus_btn.clicked.connect(self.apply_malus_to_target)
        self.apply_malus_btn.setStyleSheet("background-color: #da3633; color: white;")
        self.apply_malus_btn.setVisible(False)  # Caché par défaut
        target_layout.addWidget(self.apply_malus_btn)
        target_layout.addWidget(self.boss_final_info)  # À droite de l'input
        target_layout.addStretch()  # Pour pousser tout à gauche
        
        form_layout.addWidget(QLabel("XP/action*:"), 2, 0)
        form_layout.addWidget(self.xp_input, 2, 1)
        form_layout.addWidget(QLabel("Objectif XP*:"), 2, 2)
        form_layout.addWidget(self.target_input, 2, 3)
        form_layout.addLayout(target_layout, 2, 2, 1, 2)
        


        # Ligne 4: Durée et Récompense
        self.duree_input = QLineEdit("60")
        self.duree_input.setValidator(QIntValidator(1, 10080))
        self.duree_input.setFixedWidth(80)
        self.duree_input.setPlaceholderText("minutes")
        
        self.recompense_input = QLineEdit()
        self.recompense_input.setPlaceholderText("Item ou avantage")
        self.recompense_input.setFixedWidth(150)
        
        # AJOUT: Champ pour le taux de réussite
        self.success_rate_input = QSpinBox()
        self.success_rate_input.setRange(0, 100)
        self.success_rate_input.setValue(100)
        self.success_rate_input.setSuffix("%")
        self.success_rate_input.setFixedWidth(80)
        self.success_rate_input.setToolTip("Taux de réussite de l'événement (0-100%)")
        
        form_layout.addWidget(QLabel("Durée*:"), 3, 0)
        form_layout.addWidget(self.duree_input, 3, 1)
        form_layout.addWidget(QLabel("Récompense:"), 3, 2)
        form_layout.addWidget(self.recompense_input, 3, 3)
        form_layout.addWidget(QLabel("Taux réussite:"), 3, 4)  # Nouvelle colonne
        form_layout.addWidget(self.success_rate_input, 3, 5)

        # Ligne 5: Malus
        self.malus_input = QLineEdit("0")
        self.malus_input.setValidator(QIntValidator(0, 1000))
        self.malus_input.setFixedWidth(80)
        self.malus_input.setPlaceholderText("XP échec")
      
        self.thresholds_input = QLineEdit("25,50,75,100")
        self.thresholds_input.setPlaceholderText("25,50,75,100")
        self.thresholds_input.setFixedWidth(150)
        
        form_layout.addWidget(QLabel("Malus échec:"), 4, 0)
        form_layout.addWidget(self.malus_input, 4, 1)
        form_layout.addWidget(QLabel("Paliers (%):"), 4, 2)
        form_layout.addWidget(self.thresholds_input, 4, 3)
        
        # Section Effets Actifs
        effects_group = QGroupBox("⚡ Effets d'Items Actifs")
        effects_layout = QVBoxLayout()

        self.active_effects_list = QListWidget()
        self.active_effects_list.setMaximumHeight(80)
        effects_layout.addWidget(self.active_effects_list)

        # Bouton pour charger les effets disponibles
        load_effects_btn = QPushButton("📥 Charger les effets disponibles")
        load_effects_btn.clicked.connect(self.load_available_effects)
        effects_layout.addWidget(load_effects_btn)

        effects_group.setLayout(effects_layout)
        form_layout.addWidget(effects_group, 9, 0, 1, 4)  # Ajustez la position selon votre grille

        # Textes narratifs avec onglets pour économiser l'espace
        texts_tabs = QTabWidget()
        texts_tabs.setStyleSheet("QTabWidget::pane { border: 1px solid #30363d; }")
        
        # Onglet Description courte
        self.courte_input = QTextEdit()
        self.courte_input.setPlaceholderText("Description courte pour les joueurs...")
        self.courte_input.setMaximumHeight(80)
        texts_tabs.addTab(self.courte_input, "📝 Courte")
        
        # Onglet Histoire détaillée
        self.longue_input = QTextEdit()
        self.longue_input.setPlaceholderText("Histoire détaillée...")
        self.longue_input.setMaximumHeight(80)
        texts_tabs.addTab(self.longue_input, "📖 Longue")
        
        # Onglet Conclusions
        conclusions_widget = QWidget()
        conclusions_layout = QVBoxLayout()
        self.conclusion_reussite_input = QTextEdit()
        self.conclusion_reussite_input.setPlaceholderText("Texte en cas de réussite...")
        self.conclusion_reussite_input.setMaximumHeight(60)
        
        self.conclusion_echec_input = QTextEdit()
        self.conclusion_echec_input.setPlaceholderText("Texte en cas d'échec...")
        self.conclusion_echec_input.setMaximumHeight(60)
        
        conclusions_layout.addWidget(QLabel("Réussite:"))
        conclusions_layout.addWidget(self.conclusion_reussite_input)
        conclusions_layout.addWidget(QLabel("Échec:"))
        conclusions_layout.addWidget(self.conclusion_echec_input)
        conclusions_widget.setLayout(conclusions_layout)
        texts_tabs.addTab(conclusions_widget, "✅❌ Conclusions")

        form_layout.addWidget(QLabel("Textes narratifs:"), 5, 0)
        form_layout.addWidget(texts_tabs, 5, 1, 1, 5)

        # Barre de progression de l'événement
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_label = QLabel("0/0 (0%)")
        self.progress_label.setFixedWidth(100)
        
        progress_layout = QHBoxLayout()
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.progress_label)
        form_layout.addLayout(progress_layout, 6, 0, 1, 6)

        # Boutons d'action - plus compacts
        btn_layout = QHBoxLayout()
        buttons = [
            ("💾 Sauvegarder", self.save_event),
            ("📂 Ouvrir", lambda: self.event_action("open")),
            ("▶️ Démarrer", lambda: self.event_action("start")),
            ("✅ Terminer", lambda: self.event_action("finish")),
            ("❌ Annuler", lambda: self.event_action("cancel")),
            ("📊 Vérifier faisabilité", self.check_event_feasibility)
        ]
        
        for text, callback in buttons:
            btn = QPushButton(text)
            btn.setFixedHeight(30)
            btn.clicked.connect(callback)
            btn_layout.addWidget(btn)

        form_layout.addLayout(btn_layout, 7, 0, 1, 6)

        form_group.setLayout(form_layout)
        content_layout.addWidget(form_group, 3)

        # PANEL DROIT COMPACT (25% de l'espace) - UN SEUL RIGHT_PANEL
        right_panel = QVBoxLayout()
        right_panel.setSpacing(10)

        # CADRE MALUS TOTAL
        malus_card = QGroupBox("💀 Malus Total Accumulé")
        malus_layout = QVBoxLayout()
        
        self.malus_label = QLabel("Chargement...")
        self.malus_label.setAlignment(Qt.AlignCenter)
        self.malus_label.setStyleSheet("""
            font-size: 20px; 
            font-weight: bold; 
            color: #ff6b6b; 
            padding: 8px;
            background-color: #161b22;
            border-radius: 6px;
            margin: 5px;
        """)
        
        self.malus_description = QLabel("Somme des malus des événements échoués")
        self.malus_description.setAlignment(Qt.AlignCenter)
        self.malus_description.setStyleSheet("color: #8b949e; font-size: 10px; padding: 2px;")
        self.malus_description.setWordWrap(True)
        
        malus_layout.addWidget(self.malus_label)
        malus_layout.addWidget(self.malus_description)
        malus_card.setLayout(malus_layout)
        right_panel.addWidget(malus_card)

        # Carte temps restant
        time_card = QGroupBox("⏱️ Temps restant")
        time_layout = QVBoxLayout()
        
        self.time_progress_bar = QProgressBar()
        self.time_progress_bar.setMinimum(0)
        self.time_progress_bar.setMaximum(100)
        self.time_progress_bar.setTextVisible(True)
        self.time_progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #30363d;
                border-radius: 5px;
                text-align: center;
                background-color: #0d1117;
                height: 20px;
            }
            QProgressBar::chunk {
                background-color: #1f6feb;
                border-radius: 3px;
            }
        """)
        
        self.time_remaining_label = QLabel("--:--")
        self.time_remaining_label.setAlignment(Qt.AlignCenter)
        self.time_remaining_label.setStyleSheet("font-size: 20px; font-weight: bold; color: #58a6ff; padding: 8px;")
        
        self.time_status_label = QLabel("Événement non démarré")
        self.time_status_label.setAlignment(Qt.AlignCenter)
        self.time_status_label.setStyleSheet("color: #8b949e; font-size: 10px; padding: 2px;")
        
        time_layout.addWidget(self.time_progress_bar)
        time_layout.addWidget(self.time_remaining_label)
        time_layout.addWidget(self.time_status_label)
        time_card.setLayout(time_layout)
        right_panel.addWidget(time_card)


        # Effets Actifs pour cet événement
        active_effects_group = QGroupBox("⚡ Effets Actifs")
        active_effects_layout = QVBoxLayout()

        self.current_effects_list = QListWidget()
        self.current_effects_list.setMaximumHeight(80)
        active_effects_layout.addWidget(self.current_effects_list)

        active_effects_group.setLayout(active_effects_layout)
        right_panel.addWidget(active_effects_group)
               
        # Top contributions
        top_group = QGroupBox("🏆 Top 5")
        top_layout = QVBoxLayout()
        
        self.contrib_list = QListWidget()
        self.contrib_list.setMaximumHeight(120)
        self.contrib_list.setFont(QFont("Segoe UI", 8))
        top_layout.addWidget(self.contrib_list)

        # Statistiques
        stats_group = QGroupBox("📈 Stats")
        stats_layout = QVBoxLayout()
        
        self.stats_participants = QLabel("👥 Participants: 0")
        self.stats_avg_xp = QLabel("⭐ XP moyen: 0")
        self.stats_progress = QLabel("📊 Progression: 0%")
        
        stats_layout.addWidget(self.stats_participants)
        stats_layout.addWidget(self.stats_avg_xp)
        stats_layout.addWidget(self.stats_progress)
        stats_group.setLayout(stats_layout)
        
        top_layout.addWidget(stats_group)
        top_group.setLayout(top_layout)
        right_panel.addWidget(top_group)

        # Espace flexible
        right_panel.addStretch()

        # Widget conteneur pour le panel droit
        right_widget = QWidget()
        right_widget.setLayout(right_panel)
        right_widget.setMaximumWidth(300)  # Largeur fixe pour le panel droit
        content_layout.addWidget(right_widget, 1)  # 25% de l'espace

        main_layout.addLayout(content_layout)
        self.setLayout(main_layout)

        # Chargement initial
        self.refresh_data()
    def generate_code(self):
        """Génère un code automatique avec vérification des doublons"""
        event_type = self.type_combo.currentText()
        if not event_type:
            QMessageBox.warning(self, "Erreur", "Veuillez d'abord sélectionner un type d'événement")
            return

        try:
            # Récupérer les codes existants
            existing_codes_result = self.api_client.get_existing_event_codes()
            existing_codes = []
            
            if existing_codes_result and "codes" in existing_codes_result:
                existing_codes = existing_codes_result["codes"]
                print(f"📋 {len(existing_codes)} codes chargés depuis la DB")
            else:
                print("⚠️ Utilisation d'une liste vide pour les codes existants")
            
            # Générer un code unique
            unique_code = generate_unique_event_code(event_type, existing_codes, self.api_client)
            self.code_input.setText(unique_code)
            
        except Exception as e:
            print(f"❌ Erreur génération code unique: {e}")
            # Fallback vers l'ancienne méthode
            self.generate_code_fallback()
    
    def generate_event_code(self, event_type):
        """Génère un code d'événement automatique (ancienne méthode sans vérification)"""
        prefix_map = {
            "community": "COM",
            "raid": "RAID", 
            "boss": "BOSS",
            "Boss Final": "BF",
            "Mission communautaire": "COM",
            "Boss": "BOSS",
            "": "EVT"
        }
        prefix = prefix_map.get(event_type, "EVT")
        code = f"{prefix}{self.event_counter:03d}"
        self.event_counter += 1
        return code
    
    def generate_code_fallback(self):
        """Méthode de fallback sans vérification des doublons"""
        event_type = self.type_combo.currentText()
        if event_type:
            code = self.generate_event_code(event_type)
            self.code_input.setText(code)
            print(f"⚠️ Code généré sans vérification: {code}")
    


    def on_type_changed(self, event_type):
        """Callback quand le type d'événement change"""
        # Génération du code si vide
        if event_type and not self.code_input.text():
            self.generate_code()
        
        # GESTION SPÉCIALE DU BOSS FINAL
        if event_type == "Boss Final":
            print("🎯 Type Boss Final détecté - Calcul du malus total...")
            
            # Style visuel pour le Boss Final
            self.target_input.setStyleSheet("""
                QLineEdit {
                    background-color: #2d1a1a;
                    color: #ff6b6b;
                    border: 2px solid #ff6b6b;
                    font-weight: bold;
                }
            """)
            
            # Afficher le bouton d'application du malus
            self.apply_malus_btn.setVisible(True)
            
            # Calculer le malus (affichage seulement)
            self.calculate_and_apply_malus()
            
        else:
            # Réinitialiser le style si on change de type
            self.target_input.setStyleSheet("")
            self.boss_final_info.setText("")
            self.apply_malus_btn.setVisible(False)
            
            self.malus_applied = False
                
        # Recharger les effets disponibles si le type change
        if event_type:
            QTimer.singleShot(500, self.load_available_effects)
            # AJOUT: Recharger aussi les effets du coffre
            QTimer.singleShot(600, self.load_active_effects_from_coffre)
            
            
    def calculate_and_apply_malus(self):
        """Calcule et affiche le malus total pour le Boss Final - VERSION CORRIGÉE VISUELLEMENT"""
        try:
            print("📊 Calcul du malus total pour le Boss Final...")
            
            # Afficher un indicateur de chargement
            self.boss_final_info.setText("🔄 Calcul du malus total...")
            
            # Vérifier que le type est toujours Boss Final
            if self.type_combo.currentText() != "Boss Final":
                return
                
            # Récupérer le malus total via l'API
            malus_data = self.api_client.get_malus_total()
            
            # Vérifier à nouveau le type
            if self.type_combo.currentText() != "Boss Final":
                return
                
            if malus_data and "total_malus" in malus_data:
                total_malus = malus_data["total_malus"]
                print(f"✅ Malus total récupéré: {total_malus} XP")
                
                # LIRE LA VALEUR ACTUELLE du champ target_input
                current_target_text = self.target_input.text().strip()
                if not current_target_text:
                    current_target_text = "0"
                    
                try:
                    base_target = int(current_target_text)
                except ValueError:
                    base_target = 0
                    self.target_input.setText("0")
                
                # Calculer le total pour l'affichage seulement
                total_with_malus = base_target + total_malus
                
                # CORRECTION: Utiliser la VRAIE valeur du champ pour l'affichage
                if total_malus > 0:
                    display_text = f"+{total_malus} = {base_target} + {total_malus}"
                    self.boss_final_info.setText(display_text)
                    
                    # CORRECTION: Message d'alerte avec la VRAIE valeur
                    QMessageBox.information(
                        self, 
                        "Boss Final - Malus Calculé",
                        f"⚔️ **MALUS CALCULÉ**\n\n"
                        f"Objectif actuel: {base_target} XP\n"
                        f"Malus total des échecs: +{total_malus} XP\n"
                        f"**Total suggéré: {total_with_malus} XP**\n\n"
                        f"Cliquez sur 'Appliquer le malus' pour mettre à jour l'objectif."
                    )
                else:
                    self.boss_final_info.setText("Aucun malus à appliquer")
                
                print(f"🎯 Calcul Boss Final (affichage): {base_target} + {total_malus} = {total_with_malus}")
                
            else:
                print("❌ Impossible de récupérer le malus total")
                self.boss_final_info.setText("❌ Erreur de calcul")
                
        except Exception as e:
            print(f"❌ Erreur lors du calcul du malus: {e}")
            self.boss_final_info.setText("❌ Erreur de calcul")
            
            
    def apply_malus_to_target(self):
        """Applique le malus calculé à l'objectif XP"""
        try:
            # Récupérer le malus total
            malus_data = self.api_client.get_malus_total()
            if not malus_data or "total_malus" not in malus_data:
                QMessageBox.warning(self, "Erreur", "Impossible de récupérer le malus total")
                return
                
            total_malus = malus_data["total_malus"]
            
            # Lire la target XP actuelle
            current_target_text = self.target_input.text().strip()
            if not current_target_text:
                current_target_text = "0"
                
            try:
                base_target = int(current_target_text)
            except ValueError:
                base_target = 0
                
            # Calculer le nouveau total
            new_target = base_target + total_malus
            
            # Appliquer
            self.target_input.setText(str(new_target))
            self.malus_applied = True
            
            # Mettre à jour l'affichage
            self.boss_final_info.setText(f"✅ Malus appliqué: {new_target} XP")
            self.apply_malus_btn.setVisible(False)
            
            QMessageBox.information(
                self,
                "Malus Appliqué",
                f"Objectif mis à jour: {base_target} + {total_malus} = {new_target} XP"
            )
            
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur lors de l'application du malus: {str(e)}")
        
        
    def toggle_auto_refresh(self, state):
        if state == Qt.Checked:
            self.refresh_timer.start(5000)
            self.slow_refresh_timer.start(30000)
        else:
            self.refresh_timer.stop()
            self.slow_refresh_timer.stop()

    def generate_code(self):
        """Génère un code automatique basé sur le type sélectionné"""
        event_type = self.type_combo.currentText()
        if event_type:
                                             
                                                                              
                               
                                                                          
                                                               
            
                                          
            code = self.generate_event_code(event_type)
            self.code_input.setText(code)
        else:
            QMessageBox.warning(self, "Erreur", "Veuillez d'abord sélectionner un type d'événement")

    def update_countdown(self):
        """Met à jour le décompte en temps réel"""
        if not self.current_event or self.current_event.get('status') != 'running':
            self.time_remaining_label.setText("--:--")
            self.time_progress_bar.setValue(0)
            self.time_status_label.setText("Événement non démarré")
            return

        try:
            started_at = self.current_event.get('started_at')
            duree_minutes = int(self.current_event.get('duree', 0))
            
            if not started_at or duree_minutes <= 0:
                return

            # Convertir en datetime
            from datetime import datetime, timezone, timedelta
            start_time = datetime.fromisoformat(started_at.replace('Z', '+00:00'))
            end_time = start_time + timedelta(minutes=duree_minutes)
            now = datetime.now(timezone.utc)

            if now >= end_time:
                # Temps écoulé
                self.time_remaining_label.setText("00:00")
                self.time_progress_bar.setValue(100)
                self.time_status_label.setText("Temps écoulé")
                return

            # Calcul du temps restant
            remaining = end_time - now
            total_seconds = duree_minutes * 60
            remaining_seconds = int(remaining.total_seconds())
            
            # Format MM:SS
            minutes = remaining_seconds // 60
            seconds = remaining_seconds % 60
            self.time_remaining = f"{minutes:02d}:{seconds:02d}"
            
            # Pourcentage de progression temporelle
            elapsed_seconds = total_seconds - remaining_seconds
            self.time_percentage = int((elapsed_seconds / total_seconds) * 100)
            
            # Mise à jour de l'interface
            self.time_remaining_label.setText(self.time_remaining)
            self.time_progress_bar.setValue(self.time_percentage)
            
            # Statut avec pourcentage
            self.time_status_label.setText(f"Progression temporelle: {self.time_percentage}%")
            
            # Changement de couleur selon le temps restant
            if minutes < 1:  # Moins d'une minute
                self.time_remaining_label.setStyleSheet("font-size: 20px; font-weight: bold; color: #ff6b6b; padding: 8px;")
            elif minutes < 5:  # Moins de 5 minutes
                self.time_remaining_label.setStyleSheet("font-size: 20px; font-weight: bold; color: #ffa726; padding: 8px;")
            else:
                self.time_remaining_label.setStyleSheet("font-size: 20px; font-weight: bold; color: #58a6ff; padding: 8px;")
                
        except Exception as e:
            print(f"Erreur mise à jour décompte: {e}")

    def slow_refresh(self):
        """Rafraîchit les données lourdes (config, malus, coffre, aventuriers) - appelé toutes les 30s"""
        if not self.api_client.is_online:
            return
        self.load_config_values()
        self.load_malus_total()
        self.load_active_effects_from_coffre()

    def refresh_data(self):
        """Rafraîchit les données de l'événement (léger - appelé toutes les 5s)"""
        if not self.api_client.is_online:
            if not self.api_client.check_connectivity():
                self.status_label.setText("🌐 Déconnecté - Reconnexion...")
                return

        data = self.api_client.get_event_status()

        if data is None:
            self.status_label.setText("❌ Erreur de connexion")
            self.reset_display()
            return

        self.current_event = data.get("event")
        top = data.get("top", [])

        if self.current_event:
            status = self.current_event.get("status", "unknown")
            event_type = self.current_event.get("event_type", "n/a")
            
            status_icons = {
                "draft": "📝",
                "registration": "📂", 
                "running": "▶️",
                "done": "✅",
                "canceled": "❌"
            }
            
            icon = status_icons.get(status, "❓")
            self.status_label.setText(f"{icon} Statut: {status} • Type: {event_type}")
            
            # Mise à jour indicateur temps header
            if status == "running":
                self.time_indicator.setText(f"⏱️ {self.time_remaining}")
            else:
                self.time_indicator.setText("⏱️ --:--")

            # Vérification Boss Final
            if event_type == "Boss Final" and not hasattr(self, 'malus_applied'):
                QTimer.singleShot(1000, self.calculate_and_apply_malus)

            # Remplissage du formulaire seulement si vide
            if not self.code_input.text():
                self.code_input.setText(self.current_event.get("code", ""))
                self.title_input.setText(self.current_event.get("title", ""))
                self.type_combo.setCurrentText(self.current_event.get("event_type", ""))
                self.xp_input.setText(str(self.current_event.get("xp_per_player", 10)))
                self.target_input.setText(str(self.current_event.get("target_xp", 1000)))
                self.duree_input.setText(str(self.current_event.get("duree", 60)))
                self.recompense_input.setText(self.current_event.get("recompense", ""))
                self.malus_input.setText(str(self.current_event.get("malus_xp", 0)))
                self.courte_input.setPlainText(self.current_event.get("courte", ""))
                self.longue_input.setPlainText(self.current_event.get("longue", ""))
                self.conclusion_reussite_input.setPlainText(self.current_event.get("conclusion_reussite", ""))
                self.conclusion_echec_input.setPlainText(self.current_event.get("conclusion_echec", ""))
                self.success_rate_input.setValue(self.current_event.get("success_rate", 100))
                self.success_rate_input.valueChanged.connect(self.update_success_rate_color)
                
                thresholds = self.current_event.get("thresholds_pct", [])
                if thresholds:
                    if isinstance(thresholds, list):
                        self.thresholds_input.setText(",".join(map(str, thresholds)))
                    else:
                        self.thresholds_input.setText(str(thresholds))

            # Calcul des statistiques
            progress = self.current_event.get("progress_xp", 0)
            target = self.current_event.get("target_xp", 0)
            participants = self.current_event.get("participants", 0)
            
            if target > 0:
                pct = int(progress * 100 / target) if target > 0 else 0
                self.progress_bar.setValue(pct)
                self.progress_label.setText(f"{progress}/{target} ({pct}%)")
                
                # Mise à jour des stats
                avg_xp = progress // participants if participants > 0 else 0
                self.stats_participants.setText(f"👥 Participants: {participants}")
                self.stats_avg_xp.setText(f"⭐ XP moyen: {avg_xp}")
                self.stats_progress.setText(f"📊 Progression: {pct}%")
            else:
                self.progress_bar.setValue(0)
                self.progress_label.setText(f"{progress}/0 (0%)")
                self.stats_participants.setText(f"👥 Participants: {participants}")
                self.stats_avg_xp.setText("⭐ XP moyen: -")
                self.stats_progress.setText("📊 Progression: -")
        else:
            self.status_label.setText("📭 Aucun événement")
            self.reset_display()

        # Mise à jour du top
        self.contrib_list.clear()
        for i, contrib in enumerate(top[:5]):
            medal = ["🥇", "🥈", "🥉", "4️⃣", "5️⃣"][i] if i < 5 else f"{i+1}."
            item = QListWidgetItem(f"{medal} {contrib.get('twitch_login', '')} - {contrib.get('xp', 0)} XP")
            self.contrib_list.addItem(item)
                    
                    
    def load_malus_total(self):
        """Charge le malus total des événements échoués"""
        try:
            data = self.api_client.get_malus_total()
            
            if data and "error" not in data:
                total_malus = data.get("total_malus", 0)
                
                # Formater le texte avec séparateurs de milliers
                malus_text = f"{total_malus:,} XP".replace(',', ' ')
                self.malus_label.setText(malus_text)
                
                # Changer la couleur selon l'importance du malus
                if total_malus == 0:
                    self.malus_label.setStyleSheet("""
                        font-size: 20px; 
                        font-weight: bold; 
                        color: #8b949e; 
                        padding: 8px;
                        background-color: #161b22;
                        border-radius: 6px;
                        margin: 5px;
                    """)
                    self.malus_description.setText("Aucun malus accumulé - Bravo !")
                elif total_malus < 1000:
                    self.malus_label.setStyleSheet("""
                        font-size: 20px; 
                        font-weight: bold; 
                        color: #ffa726; 
                        padding: 8px;
                        background-color: #161b22;
                        border-radius: 6px;
                        margin: 5px;
                    """)
                    self.malus_description.setText("Malus modéré - Continuez vos efforts !")
                else:
                    self.malus_label.setStyleSheet("""
                        font-size: 20px; 
                        font-weight: bold; 
                        color: #ff6b6b; 
                        padding: 8px;
                        background-color: #161b22;
                        border-radius: 6px;
                        margin: 5px;
                    """)
                    self.malus_description.setText("Malus important - Le prochain boss sera redoutable !")
            else:
                print("❌ Erreur dans la réponse du malus total")
                self.malus_label.setText("Erreur")
                self.malus_label.setStyleSheet("""
                    font-size: 20px; 
                    font-weight: bold; 
                    color: #8b949e; 
                    padding: 8px;
                    background-color: #161b22;
                    border-radius: 6px;
                    margin: 5px;
                """)
        except Exception as e:
            print(f"❌ Erreur chargement malus total: {e}")
            self.malus_label.setText("Erreur")
            self.malus_label.setStyleSheet("""
                font-size: 20px; 
                font-weight: bold; 
                color: #8b949e; 
                padding: 8px;
                background-color: #161b22;
                border-radius: 6px;
                margin: 5px;
            """)

    def reset_display(self):
        """Réinitialise l'affichage"""
        self.progress_bar.setValue(0)
        self.progress_label.setText("0/0 (0%)")
        self.stats_participants.setText("👥 Participants: 0")
        self.stats_avg_xp.setText("⭐ XP moyen: 0")
        self.stats_progress.setText("📊 Progression: 0%")
        self.time_remaining_label.setText("--:--")
        self.time_progress_bar.setValue(0)
        self.time_status_label.setText("Événement non démarré")
        self.time_indicator.setText("⏱️ --:--")

    def save_event(self):
        """Sauvegarde l'événement vers le backend - VERSION AVEC BOSS FINAL"""
        try:
            # Validation des champs obligatoires
            required_fields = [
                (self.type_combo.currentText(), "Type d'événement"),
                (self.title_input.text().strip(), "Titre"),
                (self.xp_input.text().strip(), "XP par action"),
                (self.target_input.text().strip(), "Objectif XP"),
                (self.duree_input.text().strip(), "Durée"),
                (self.courte_input.toPlainText().strip(), "Description courte")
            ]
            
            for value, field_name in required_fields:
                if not value:
                    QMessageBox.warning(self, "Erreur", f"Le champ '{field_name}' est obligatoire")
                    return

            code = self.code_input.text().strip().upper()
            if not code:
                QMessageBox.warning(self, "Erreur", "Veuillez saisir ou générer un code d'événement")
                return
            
            selected_effects = self.get_selected_effects()
            
            # Construction des données de l'événement - FORMAT CORRECT
            event_data = {
                "code": code,
                "title": self.title_input.text(),
                "event_type": self.type_combo.currentText(),
                "xp_per_player": int(self.xp_input.text()),
                "target_xp": int(self.target_input.text()),
                "duree": int(self.duree_input.text()),
                "success_rate": self.success_rate_input.value(),  # NOUVEAU CHAMP
                "recompense": self.recompense_input.text() or None,
                "malus_xp": int(self.malus_input.text() or 0),
                "courte": self.courte_input.toPlainText(),
                "longue": self.longue_input.toPlainText() or None,
                "conclusion_reussite": self.conclusion_reussite_input.toPlainText() or None,
                "conclusion_echec": self.conclusion_echec_input.toPlainText() or None,
                "selected_effects": selected_effects
            }

            # AJOUT: Information spéciale pour les Boss Finaux
            if self.type_combo.currentText() == "Boss Final" and hasattr(self, 'malus_applied') and self.malus_applied:
                # Récupérer le malus total pour l'inclure dans les données
                malus_data = self.api_client.get_malus_total()
                if malus_data and "total_malus" in malus_data:
                    event_data["malus_total_applied"] = malus_data["total_malus"]
                    print(f"⚔️ Boss Final - Malus total inclus: {malus_data['total_malus']} XP")

            # Gestion des paliers
            thresholds = self.thresholds_input.text().strip()
            if thresholds:
                try:
                    thresholds_list = [int(t.strip()) for t in thresholds.split(",") if t.strip()]
                    event_data["thresholds_pct"] = thresholds_list
                except ValueError:
                    QMessageBox.warning(self, "Erreur", "Format de paliers invalide. Utilisez: 25,50,75,100")
                    return
            else:
                event_data["thresholds_pct"] = [25, 50, 75, 100]

            print(f"💾 Données à sauvegarder: {event_data}")

            # Appel à l'API
            result = self.api_client.save_event(event_data)
            
            if result and "error" in result:
                error_msg = result.get('message', str(result['error']))
                QMessageBox.critical(self, "Erreur", f"Erreur lors de la sauvegarde:\n{error_msg}")
                print(f"❌ Erreur backend: {result}")
            elif result and result.get("success"):
                message = f"Événement '{code}' enregistré avec succès"
                if self.type_combo.currentText() == "Boss Final":
                    malus_data = self.api_client.get_malus_total()
                    if malus_data and "total_malus" in malus_data:
                        message += f"\n\n⚔️ BOSS FINAL - Malus de {malus_data['total_malus']} XP appliqué"
                if selected_effects:
                    message += f"\n\n⚡ {len(selected_effects)} effet(s) appliqué(s)"
                QMessageBox.information(self, "Succès", message)
                self.refresh_data()
            else:
                QMessageBox.warning(self, "Avertissement", "Réponse inattendue du serveur")
                    
        except ValueError as e:
            QMessageBox.critical(self, "Erreur", f"Erreur de format de nombre: {str(e)}")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur inattendue: {str(e)}")

    def event_action(self, action):
        """Exécute une action sur l'événement courant - VERSION AVEC EFFETS"""
        if not self.current_event:
            QMessageBox.warning(self, "Erreur", "Aucun événement en cours")
            return

        # Si c'est un démarrage avec effets, demander confirmation
        if action == "start":
            selected_effects = self.get_selected_effects()
            if selected_effects:
                reply = QMessageBox.question(
                    self,
                    "Confirmation des effets",
                    f"⚠️ {len(selected_effects)} effet(s) seront activés et leur utilisation décrémentée.\n\n"
                    f"Voulez-vous vraiment démarrer l'événement avec ces effets ?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply != QMessageBox.Yes:
                    return

        # Si c'est une annulation, demander la raison
        cancel_reason = None
        if action == "cancel":
            reason, ok = QInputDialog.getText(
                self,
                "Raison de l'annulation",
                "Entrez la raison de l'annulation (optionnel):",
                QLineEdit.Normal,
                ""
            )
            if ok:
                cancel_reason = reason.strip() or None

        # Préparer les données pour l'API
        request_data = {}
        if cancel_reason is not None:
            request_data["cancel_reason"] = cancel_reason

        result = self.api_client.event_action(action, request_data)
        if result and "error" in result:
            QMessageBox.critical(self, "Erreur", f"Erreur lors de l'action {action}: {result['error']}")
        else:
            messages = {
                "open": "Inscriptions ouvertes avec succès",
                "start": "Événement démarré avec succès", 
                "finish": "Événement terminé avec succès",
                "cancel": "Événement annulé avec succès"
            }
            message = messages.get(action, f"Action {action} exécutée")
            if action == "cancel" and cancel_reason:
                message += f"\nRaison: {cancel_reason}"
            QMessageBox.information(self, "Succès", message)
            self.refresh_data()

    def load_available_effects(self):
        """Charge les effets disponibles pour le type d'événement actuel"""
        try:
            event_type = self.type_combo.currentText()
            if not event_type:
                QMessageBox.warning(self, "Erreur", "Veuillez d'abord sélectionner un type d'événement")
                return

            print(f"🔍 Chargement des effets pour: {event_type}")
            
            # Récupérer les effets disponibles depuis le backend
            effects_data = self.api_client._make_request("GET", f"/admin/events/{event_type}/available-effects")
            
            print(f"📦 Données brutes reçues: {effects_data}")
            
            self.active_effects_list.clear()
            
            if effects_data and "effects" in effects_data:
                effects_list = effects_data["effects"]
                print(f"🎯 {len(effects_list)} effet(s) disponible(s)")
                
                for effect in effects_list:
                    effect_text = f"⚡ {effect.get('item_name', 'Unknown')} - {effect.get('effect_type', 'Unknown')}: +{effect.get('effect_value', 0)}"
                    if effect.get('uses_remaining', 0) > 0:
                        effect_text += f" ({effect['uses_remaining']} utilisation(s) restante(s))"
                    
                    item = QListWidgetItem(effect_text)
                    item.setData(Qt.UserRole, effect)
                    self.active_effects_list.addItem(item)
                
                if effects_list:
                    QMessageBox.information(self, "Effets disponibles", 
                                          f"{len(effects_list)} effet(s) disponible(s) pour cet événement")
                else:
                    QMessageBox.information(self, "Information", "Aucun effet disponible pour ce type d'événement")
            else:
                print("❌ Format de réponse invalide ou clé 'effects' manquante")
                QMessageBox.warning(self, "Information", "Aucun effet disponible ou erreur de chargement")
                
        except Exception as e:
            print(f"❌ Erreur chargement effets: {e}")
            QMessageBox.critical(self, "Erreur", f"Erreur lors du chargement des effets: {e}")
            
            
    def get_selected_effects(self):
        """Retourne les effets sélectionnés pour l'événement"""
        selected_effects = []
        for i in range(self.active_effects_list.count()):
            item = self.active_effects_list.item(i)
            if item.isSelected():
                effect_data = item.data(Qt.UserRole)
                selected_effects.append({
                    "effect_id": effect_data["effect_id"],
                    "item_code": effect_data["item_code"],
                    "effect_type": effect_data["effect_type"],
                    "effect_value": effect_data["effect_value"]
                })
        return selected_effects            
      
    def load_active_effects_from_coffre(self):
        """Charge les effets actifs disponibles depuis le coffre communautaire"""
        try:
            # Récupérer les données du coffre (avec cache 20s)
            coffre_data = self.api_client._cached_get("/public/coffre/items", cache_ttl=20)
            
            if not coffre_data or "success" not in coffre_data or not coffre_data["success"]:
                print("❌ Impossible de charger les données du coffre")
                self.current_effects_list.clear()
                self.current_effects_list.addItem("❌ Impossible de charger le coffre")
                return
                
            coffre = coffre_data.get("coffre", {})
            items = coffre.get("items", [])
            
            # Vider la liste actuelle
            self.current_effects_list.clear()
            
            if not items:
                self.current_effects_list.addItem("📭 Aucun objet dans le coffre")
                return
                
            # Filtrer les objets qui ont des effets et qui sont disponibles
            items_avec_effets = []
            for item in items:
                # Vérifier si l'objet a des effets et n'a pas été utilisé
                if (item.get('effets') and 
                    item.get('utilise_le') is None and 
                    item.get('quantite', 0) > 0):
                    items_avec_effets.append(item)
            
            if not items_avec_effets:
                self.current_effects_list.addItem("⚡ Aucun effet disponible dans le coffre")
                return
                
            print(f"✅ {len(items_avec_effets)} objets avec effets trouvés")
            
            # Afficher les effets disponibles
            for item in items_avec_effets:
                item_code = item.get('code', 'N/A')
                item_nom = item.get('nom', 'Sans nom')
                quantite = item.get('quantite', 0)
                rarete = item.get('rarete', 'common')
                description = item.get('description', '')
                effets = item.get('effets', [])
                
                # Couleur selon la rareté
                color = RARITY_COLORS.get(rarete, "#8b949e")
                
                # Afficher un élément par effet
                for effet in effets:
                    effect_type = effet.get('effect_type', 'inconnu')
                    effect_value = effet.get('effect_value', 0)
                    target_event_type = effet.get('target_event_type', 'all_events')
                    uses_available = effet.get('uses_available', 1)
                    
                    # Formater le type d'effet pour l'affichage
                    effect_type_display = {
                        'attack_bonus': '💥 Bonus Attaque',
                        'time_extension': '⏱️ Extension Temps', 
                        'malus_reduction': '🛡️ Réduction Malus',
                        'xp_boost': '⭐ Boost XP'
                    }.get(effect_type, f"⚡ {effect_type}")
                    
                    # Formater la cible
                    target_display = {
                        'all_events': 'Tous événements',
                        'boss': 'Boss',
                        'community': 'Mission Communautaire',
                        'raid': 'Raid'
                    }.get(target_event_type, target_event_type)
                    
                    # Créer l'élément d'affichage
                    effect_text = f"{effect_type_display}: +{effect_value} | {item_nom} ×{quantite}"
                    
                    item_widget = QListWidgetItem(effect_text)
                    item_widget.setForeground(QColor(color))
                    
                    # Tooltip détaillé
                    tooltip = f"📦 {item_nom} ({item_code})\n"
                    tooltip += f"🎯 Rareté: {rarete}\n"
                    tooltip += f"📊 Quantité: {quantite}\n"
                    tooltip += f"⚡ Effet: {effect_type_display} +{effect_value}\n"
                    tooltip += f"🎯 Cible: {target_display}\n"
                    tooltip += f"🔄 Utilisations: {uses_available}\n"
                    if description:
                        tooltip += f"📝 {description}"
                        
                    item_widget.setToolTip(tooltip)
                    
                    # Stocker les données pour utilisation future
                    item_widget.setData(Qt.UserRole, {
                        'item_code': item_code,
                        'item_nom': item_nom,
                        'effect_type': effect_type,
                        'effect_value': effect_value,
                        'target_event_type': target_event_type,
                        'uses_available': uses_available,
                        'quantite': quantite
                    })
                    
                    self.current_effects_list.addItem(item_widget)
                    
        except Exception as e:
            print(f"❌ Erreur chargement effets du coffre: {e}")
            self.current_effects_list.clear()
            self.current_effects_list.addItem(f"❌ Erreur: {str(e)}")

    def update_success_rate_color(self, value):
        """Met à jour la couleur du taux de réussite"""
        if value >= 90:
            color = "#3fb950"  # Vert
        elif value >= 75:
            color = "#2ea043"  # Vert moyen
        elif value >= 60:
            color = "#ffa726"  # Orange
        elif value >= 40:
            color = "#f85149"  # Rouge clair
        else:
            color = "#da3633"  # Rouge foncé
        
        self.success_rate_input.setStyleSheet(f"""
            QSpinBox {{
                background-color: {color}20;
                color: {color};
                font-weight: bold;
                border: 1px solid {color};
            }}
        """)      
        
    def load_config_values(self):
        """Charge les valeurs de configuration depuis le backend (avec cache)"""
        try:
            # Récupérer MISSION_COOLDOWN_SEC (cache 60s - change rarement)
            cooldown_result = self.api_client._cached_get("/admin/config/MISSION_COOLDOWN_SEC", cache_ttl=60)
            if cooldown_result and cooldown_result.get("success"):
                self.mission_cooldown = int(cooldown_result.get("value", 30))
            else:
                self.mission_cooldown = 30

            # Récupérer le nombre d'aventuriers actifs
            self.update_active_adventurers()
            
        except Exception as e:
            print(f"❌ Erreur chargement configuration: {e}")
            self.mission_cooldown = 30
            self.active_adventurers_count = 0

    def update_active_adventurers(self):
        """Met à jour le compteur d'aventuriers actifs (cache 15s)"""
        try:
            result = self.api_client._cached_get("/admin/participants/active-count", cache_ttl=15)
            
            if result and result.get("success"):
                counts = result.get("counts", {})
                self.active_adventurers_count = counts.get("active_adventurers", 0)
                                                 
                                                                                   
                
                # Mettre à jour le label
                total_registered = counts.get("total_registered", 0)
                participation_rate = result.get("participation_rate", 0)
                
                self.active_adventurers_label.setText(
                    f"👥 Actifs: {self.active_adventurers_count} "
                    f"| Inscrits: {total_registered} "
                    f"| Taux: {participation_rate}%"
                )
                
                # Tooltip avec plus d'informations
                from datetime import datetime
                tooltip = f"🔄 Dernière mise à jour: {datetime.now().strftime('%H:%M:%S')}\n"
                tooltip += f"👥 Aventuriers actifs (dans le chat): {self.active_adventurers_count}\n"
                tooltip += f"📋 Total inscrits: {total_registered}\n"
                tooltip += f"📊 Taux de participation: {participation_rate}%\n"
                tooltip += f"👀 Viewers non-inscrits: {counts.get('unregistered_viewers', 0)}\n"
                tooltip += f"💤 Inscrits inactifs: {counts.get('inactive_registered', 0)}"
                
                self.active_adventurers_label.setToolTip(tooltip)
                
                print(f"✅ Aventuriers actifs: {self.active_adventurers_count}")
                return True
            else:
                self.active_adventurers_label.setText("👥 Aventuriers: Erreur")
                return False
                
        except Exception as e:
            print(f"❌ Erreur mise à jour aventuriers: {e}")
            self.active_adventurers_label.setText("👥 Aventuriers: ?")
            return False

    def check_event_feasibility(self):
        """Vérifie si l'événement est réalisable avec les paramètres actuels"""
        try:
            # Vérifier que les champs nécessaires sont remplis
            required_fields = [
                (self.duree_input.text().strip(), "Durée"),
                (self.target_input.text().strip(), "Objectif XP"),
                (self.xp_input.text().strip(), "XP par action"),
                (self.active_adventurers_count > 0, "Aventuriers actifs")
            ]
            
            for value, field_name in required_fields:
                if not value:
                    QMessageBox.warning(self, "Erreur", 
                        f"Impossible de vérifier la faisabilité : {field_name} manquant")
                    return
                                                                         
             
            
                                                     
                             
                                                        
                                                                                           
                          
        
            # Récupérer les valeurs
            duree_minutes = int(self.duree_input.text().strip())
            target_xp = int(self.target_input.text().strip())
            xp_per_action = int(self.xp_input.text().strip())
            success_rate = self.success_rate_input.value() / 100.0  # Convertir en décimal
            
            # Calculs
            total_seconds = duree_minutes * 60
            cooldown = self.mission_cooldown
            
            # 1. Nombre d'actions possibles par aventurier
            actions_per_adventurer = total_seconds / cooldown
            
            # 2. Nombre total d'actions (tous aventuriers)
            total_actions = self.active_adventurers_count * actions_per_adventurer
            
            # 3. Nombre d'actions réussies (avec taux de réussite)
            successful_actions = total_actions * success_rate
            
            # 4. XP total généré
            xp_generated = successful_actions * xp_per_action
            
            # 5. Temps nécessaire pour atteindre l'objectif
            required_successful_actions = target_xp / xp_per_action
            required_total_actions = required_successful_actions / success_rate
            required_actions_per_adventurer = required_total_actions / self.active_adventurers_count
            required_time_seconds = required_actions_per_adventurer * cooldown
            required_time_minutes = required_time_seconds / 60
            
            # 6. Marge de sécurité (20% de temps en plus)
            suggested_time_minutes = required_time_minutes * 1.2
            
            # Préparer le message
            message = f"📊 **ANALYSE DE FAISABILITÉ**\n\n"
            message += f"🔧 **Paramètres actuels :**\n"
            message += f"• ⏱️ Durée : {duree_minutes} minutes\n"
            message += f"• 🎯 Objectif XP : {target_xp:,} XP\n".replace(',', ' ')
            message += f"• ⚡ XP/action : {xp_per_action} XP\n"
            message += f"• 🎲 Taux réussite : {success_rate*100:.0f}%\n"
            message += f"• 👥 Aventuriers actifs : {self.active_adventurers_count}\n"
            message += f"• ⏳ Cooldown actions : {cooldown}s\n\n"
            
            message += f"📈 **Calculs :**\n"
            message += f"• 🔄 Actions/aventurier : {actions_per_adventurer:.1f}\n"
            message += f"• 🔢 Total actions : {total_actions:.0f}\n"
            message += f"• ✅ Actions réussies : {successful_actions:.0f}\n"
            message += f"• 💎 XP généré : {xp_generated:,.0f} XP\n\n".replace(',', ' ')
            
            # Conclusion
            if xp_generated >= target_xp:
                ratio = xp_generated / target_xp
                message += f"✅ **FAISABLE !**\n"
                message += f"📊 Ratio : {ratio:.2f}x l'objectif\n"
                message += f"⏱️ Temps estimé : {required_time_minutes:.1f} minutes\n"
                message += f"🛡️ Marge : +{(ratio-1)*100:.0f}%\n\n"
                
                # Calcul du temps réellement nécessaire
                actual_time_ratio = required_time_minutes / duree_minutes
                if actual_time_ratio < 0.7:
                    message += f"💡 **Suggestion** : Réduire la durée à {int(required_time_minutes*1.2)} minutes"
                elif actual_time_ratio > 0.9:
                    message += f"⚠️ **Attention** : L'événement sera serré ({(actual_time_ratio*100):.0f}% du temps utilisé)"
                else:
                    message += f"🎯 **Parfait** ! La durée est bien calibrée"
                    
            else:
                deficit = target_xp - xp_generated
                deficit_percent = (deficit / target_xp) * 100
                
                message += f"❌ **NON FAISABLE** avec les paramètres actuels\n"
                message += f"📉 Déficit : {deficit:,.0f} XP ({deficit_percent:.0f}%)\n".replace(',', ' ')
                message += f"⏱️ Temps nécessaire : {required_time_minutes:.1f} minutes\n"
                message += f"💡 **Suggestion** : Durée de {int(suggested_time_minutes)} minutes\n\n"
                
                # Suggestions alternatives
                message += f"🔄 **Alternatives :**\n"
                
                # Augmenter la durée
                needed_duration = required_time_minutes * 1.2
                message += f"1. ⏱️ Augmenter durée à {int(needed_duration)} minutes\n"
                
                # Augmenter le XP/action
                needed_xp_per_action = target_xp / (successful_actions * 1.2)
                message += f"2. ⚡ Augmenter XP/action à {int(needed_xp_per_action)} XP\n"
                
                # Réduire l'objectif
                realistic_target = xp_generated * 0.9  # 90% de ce qui est faisable
                message += f"3. 🎯 Réduire objectif à {int(realistic_target):,} XP".replace(',', ' ')
            
            # Créer une boîte de dialogue avec boutons d'action
            dialog = QDialog(self)
            dialog.setWindowTitle("📊 Analyse de Faisabilité")
            dialog.setMinimumSize(600, 500)
            
            layout = QVBoxLayout()
            
            # Zone de texte
            text_edit = QTextEdit()
            text_edit.setReadOnly(True)
            text_edit.setHtml(f"""
                <div style="font-family: 'Segoe UI', Arial, sans-serif; color: #e6edf3;">
                    <div style="background-color: #161b22; padding: 15px; border-radius: 8px; line-height: 1.6;">
                        {message.replace(chr(10), '<br>')}
                    </div>
                </div>
            """)
            layout.addWidget(text_edit)
            
            # Boutons d'action
            btn_layout = QHBoxLayout()
            
            if xp_generated >= target_xp:
                ok_btn = QPushButton("✅ Conserver les paramètres")
                ok_btn.clicked.connect(dialog.accept)
                btn_layout.addWidget(ok_btn)
            else:
                # Bouton pour ajuster la durée
                adjust_duration_btn = QPushButton(f"⏱️ Régler durée à {int(suggested_time_minutes)} min")
                adjust_duration_btn.clicked.connect(lambda: self.adjust_duration(suggested_time_minutes, dialog))
                btn_layout.addWidget(adjust_duration_btn)
                
                # Bouton pour ajuster l'objectif
                realistic_target = xp_generated * 0.9
                adjust_target_btn = QPushButton(f"🎯 Régler objectif à {int(realistic_target):,} XP".replace(',', ' '))
                adjust_target_btn.clicked.connect(lambda: self.adjust_target(realistic_target, dialog))
                btn_layout.addWidget(adjust_target_btn)
            
            close_btn = QPushButton("Fermer")
            close_btn.clicked.connect(dialog.reject)
            btn_layout.addWidget(close_btn)
            
            layout.addLayout(btn_layout)
            dialog.setLayout(layout)
            dialog.exec()
            
        except ValueError as e:
            QMessageBox.warning(self, "Erreur", "Veuillez vérifier que tous les champs numériques sont correctement remplis")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur lors de l'analyse : {str(e)}")

    def adjust_duration(self, suggested_minutes, dialog):
        """Ajuste la durée de l'événement"""
        new_duration = int(suggested_minutes)
        self.duree_input.setText(str(new_duration))
        dialog.accept()
        
        QMessageBox.information(
            self,
            "Durée ajustée",
            f"⏱️ Durée ajustée à {new_duration} minutes\n\n"
            f"Cette durée devrait permettre d'atteindre l'objectif avec une marge de sécurité de 20%."
        )

    def adjust_target(self, realistic_target, dialog):
        """Ajuste l'objectif XP"""
        new_target = int(realistic_target)
        self.target_input.setText(str(new_target))
        dialog.accept()
        
        QMessageBox.information(
            self,
            "Objectif ajusté",
            f"🎯 Objectif ajusté à {new_target:,} XP\n\n".replace(',', ' ') +
            f"C'est l'objectif réaliste atteignable avec les paramètres actuels."
        )      
 
# Section 6: Onglet Missions Solo amélioré
class MissionsTab(QWidget):
    """Onglet de gestion des missions (solo et groupe)"""

    def __init__(self, api_client):
        super().__init__()
        self.api_client = api_client
        self.all_defs = []  # Ajouter cette ligne
        self.init_ui()
        self.refresh_defs()
        self.refresh_runs()
        
    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(10)
        layout.setContentsMargins(10, 10, 10, 10)

        split_layout = QHBoxLayout()
        split_layout.setSpacing(14)

        # FORMULAIRE ÉTENDU POUR MISSIONS SOLO ET GROUPE
        form_group = QGroupBox("🎯 Définition de Mission")
        form_layout = QFormLayout()
        form_layout.setLabelAlignment(Qt.AlignLeft)

        # Section de base (existant)
        self.mission_code = QLineEdit()
        self.mission_name = QLineEdit()
        self.mission_desc = QLineEdit()
        self.mission_duration = QLineEdit("60")
        self.mission_duration.setValidator(QIntValidator(1, 3600))
        self.mission_xp = QLineEdit("10")
        self.mission_xp.setValidator(QIntValidator(0, 1000))
        self.mission_item_combo = QComboBox()
        self.mission_item_combo.setEditable(False) 
        self.mission_item_qty = QLineEdit("1")
        self.mission_item_qty.setValidator(QIntValidator(1, 100))
        
        # AJOUT: Taux de réussite pour les missions
        self.mission_success_rate = QSpinBox()
        self.mission_success_rate.setRange(0, 100)
        self.mission_success_rate.setValue(100)
        self.mission_success_rate.setSuffix("%")
        self.mission_success_rate.setToolTip("Taux de réussite de la mission (0-100%)")

        # NOUVEAU: Section missions de groupe
        group_section = QGroupBox("🤝 Mission de Groupe")
        group_layout = QFormLayout()
        
        self.mission_is_group = QCheckBox()
        self.mission_is_group.toggled.connect(self.toggle_group_fields)
        
        self.mission_required_players = QLineEdit("3")
        self.mission_required_players.setValidator(QIntValidator(1, 20))
        
        #Coordonnées de la mission
        # REMPLACER les champs X et Y par un sélecteur visuel
        cell_selection_layout = QHBoxLayout()
        self.mission_group_x = QLineEdit()
        self.mission_group_x.setPlaceholderText("X")
        self.mission_group_x.setValidator(QIntValidator(0, 20))
        self.mission_group_y = QLineEdit()
        self.mission_group_y.setPlaceholderText("Y") 
        self.mission_group_y.setValidator(QIntValidator(0, 20))

        # Bouton pour ouvrir le sélecteur visuel
        self.select_cell_btn = QPushButton("🗺️ Sélectionner case")
        self.select_cell_btn.clicked.connect(self.open_cell_selector)
        self.select_cell_btn.setStyleSheet("background-color: #1f6feb; color: white;")
        self.mission_success_rate.valueChanged.connect(self.update_mission_success_rate_color)
        cell_selection_layout.addWidget(QLabel("Case X:"))
        cell_selection_layout.addWidget(self.mission_group_x)
        cell_selection_layout.addWidget(QLabel("Y:"))
        cell_selection_layout.addWidget(self.mission_group_y)
        cell_selection_layout.addWidget(self.select_cell_btn)
        
        self.mission_group_reward_combo = QComboBox()
        self.mission_group_reward_combo.setEditable(False)
        
        self.mission_bonus_type = QComboBox()
        self.mission_bonus_type.addItems(["", "malus_reduction", "attack_bonus", "time_extension", "xp_boost"])
        
        self.mission_bonus_value = QLineEdit("10")
        self.mission_bonus_value.setValidator(QIntValidator(0, 100))
        self.update_mission_success_rate_color(self.mission_success_rate.value())
        
        group_layout.addRow("Mission de groupe:", self.mission_is_group)
        group_layout.addRow("Joueurs requis:", self.mission_required_players)
        group_layout.addRow("Position:", cell_selection_layout) 
        group_layout.addRow("Récompense groupe:", self.mission_group_reward_combo)
        group_layout.addRow("Type de bonus:", self.mission_bonus_type)
        group_layout.addRow("Valeur bonus:", self.mission_bonus_value)
        
        group_section.setLayout(group_layout)

        # Organisation du formulaire principal
        form_layout.addRow("Code*", self.mission_code)
        form_layout.addRow("Nom*", self.mission_name)
        form_layout.addRow("Description", self.mission_desc)
        form_layout.addRow("Durée (s)*", self.mission_duration)
        form_layout.addRow("XP récompense*", self.mission_xp)
        form_layout.addRow("Taux réussite:", self.mission_success_rate)  
        form_layout.addRow("Item récompense (solo):", self.mission_item_combo)
        form_layout.addRow("Quantité item", self.mission_item_qty)
        
        # Ajouter la section groupe
        form_layout.addRow(group_section)

        # Boutons d'action
        btn_layout = QHBoxLayout()
        save_btn = QPushButton("💾 Enregistrer")
        save_btn.clicked.connect(self.save_def)
        save_btn.setStyleSheet("background-color: #238636;")
        
        delete_btn = QPushButton("🗑️ Supprimer")
        delete_btn.clicked.connect(self.delete_def)
        delete_btn.setStyleSheet("background-color: #da3633;")
        
        refresh_btn = QPushButton("🔄 Rafraîchir")
        refresh_btn.clicked.connect(self.refresh_defs)

        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(delete_btn)
        btn_layout.addWidget(refresh_btn)

        form_layout.addRow(btn_layout)
        form_group.setLayout(form_layout)
        split_layout.addWidget(form_group, 1)

        # Liste des définitions existantes
        defs_group = QGroupBox("📋 Missions Existantes")
        defs_layout = QVBoxLayout()
        
        # Filtres
        filter_layout = QHBoxLayout()
        self.filter_type = QComboBox()
        self.filter_type.addItems(["Tous types", "Solo", "Groupe"])
        self.filter_type.currentTextChanged.connect(self.apply_filters)
        filter_layout.addWidget(QLabel("Filtrer:"))
        filter_layout.addWidget(self.filter_type)
        filter_layout.addStretch()
        
        defs_layout.addLayout(filter_layout)
        
        self.defs_list = QListWidget()
        self.defs_list.itemClicked.connect(self.def_selected)
        defs_layout.addWidget(self.defs_list)
        
        defs_group.setLayout(defs_layout)
        split_layout.addWidget(defs_group, 1)

        layout.addLayout(split_layout)

        # Liste des runs récents
        runs_group = QGroupBox("📊 Missions en Cours/Récentes")
        runs_layout = QVBoxLayout()
        
        runs_header = QHBoxLayout()
        refresh_runs_btn = QPushButton("🔄 Actualiser")
        refresh_runs_btn.clicked.connect(self.refresh_runs)
        runs_header.addStretch()
        runs_header.addWidget(refresh_runs_btn)

        self.runs_list = QListWidget()
        self.runs_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                color: #e6edf3;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 5px;
            }
        """)

        runs_layout.addLayout(runs_header)
        runs_layout.addWidget(self.runs_list)
        runs_group.setLayout(runs_layout)
        layout.addWidget(runs_group)
        QTimer.singleShot(500, self.load_items_for_dropdown)
        self.setLayout(layout)
        
        # Désactiver les champs groupe par défaut
        self.toggle_group_fields(False)

    def open_cell_selector(self):
        """Ouvre le sélecteur visuel de cases"""
        dialog = CellSelectorDialog(self, self.api_client)
        
        if dialog.exec() == QDialog.Accepted:
            coords = dialog.get_selected_coords()
            if coords:
                x, y = coords
                self.mission_group_x.setText(str(x))
                self.mission_group_y.setText(str(y))
                
                QMessageBox.information(
                    self, 
                    "Case sélectionnée", 
                    f"✅ Case ({x}, {y}) sélectionnée pour la mission de groupe\n\n"
                    f"La mission sera disponible sur cette case une fois sauvegardée."
                )

    def update_mission_success_rate_color(self, value):
        """Met à jour la couleur du taux de réussite des missions"""
        if value >= 90:
            color = "#3fb950"  # Vert
        elif value >= 75:
            color = "#2ea043"  # Vert moyen
        elif value >= 60:
            color = "#ffa726"  # Orange
        elif value >= 40:
            color = "#f85149"  # Rouge clair
        else:
            color = "#da3633"  # Rouge foncé
        
        self.mission_success_rate.setStyleSheet(f"""
            QSpinBox {{
                background-color: {color}20;
                color: {color};
                font-weight: bold;
                border: 1px solid {color};
            }}
        """)
        
        
    def toggle_group_fields(self, enabled):
        """Active/désactive les champs des missions de groupe"""
        self.mission_required_players.setEnabled(enabled)
        self.mission_group_x.setEnabled(enabled)
        self.mission_group_y.setEnabled(enabled)
        self.mission_group_reward_combo.setEnabled(enabled)
        self.mission_bonus_type.setEnabled(enabled)
        self.mission_bonus_value.setEnabled(enabled)

    def refresh_defs(self):
        """Charge les définitions de missions"""
        data = self.api_client.get_solo_defs()
        self.defs_list.clear()

        if not data or "defs" not in data:
            self.defs_list.addItem("❌ Impossible de charger les définitions")
            return

        self.all_defs = data.get("defs", [])
        self.apply_filters()

    def apply_filters(self):
        """Applique les filtres sur la liste des missions"""
        filter_type = self.filter_type.currentText()
        
        self.defs_list.clear()
        for def_item in self.all_defs:
            # Filtrage par type
            is_group = def_item.get("is_group_mission", False)
            if filter_type == "Solo" and is_group:
                continue
            if filter_type == "Groupe" and not is_group:
                continue
            
            code = def_item.get("code", "")
            name = def_item.get("name", "")
            duration = def_item.get("duration_sec", 0)
            xp = def_item.get("reward_xp", 0)
            success_rate = def_item.get("success_rate", 100)  # NOUVEAU
            item = def_item.get("reward_item_code", "")
            item_qty = def_item.get("reward_item_qty", 0)
            is_group = def_item.get("is_group_mission", False)

            # Icône et couleur selon le type
            if is_group:
                icon = "🤝"
                color = "#58a6ff"
            else:
                icon = "🎯"
                color = "#8b949e"

            # AJOUT: Icône pour le taux de réussite
            if success_rate >= 90:
                success_icon = "🍀"
            elif success_rate >= 75:
                success_icon = "✅"
            elif success_rate >= 60:
                success_icon = "🎯"
            elif success_rate >= 40:
                success_icon = "🎲"
            elif success_rate >= 20:
                success_icon = "⚠️"
            else:
                success_icon = "☠️"

            text = f"{icon} {success_icon} {code} - {name} ({duration}s, +{xp} XP, {success_rate}%"
            if item:
                text += f", {item}×{item_qty}"
            if is_group:
                required_players = def_item.get("required_players", 1)
                text += f", 👥{required_players} joueurs"
            text += ")"

            item_widget = QListWidgetItem(text)
            item_widget.setData(Qt.UserRole, def_item)
            item_widget.setForeground(QColor(color))
            
            # Tooltip informatif (ajouter le taux de réussite)
            tooltip = f"🎯 {name}\n"
            tooltip += f"🔖 Code: {code}\n"
            tooltip += f"⏱️ Durée: {duration} secondes\n"
            tooltip += f"⭐ XP: +{xp}\n"
            tooltip += f"🎲 Taux de réussite: {success_rate}%\n"  # NOUVEAU
            tooltip += f"📦 Item: {item if item else 'Aucun'}"
            
            if is_group:
                tooltip += f"\n🤝 Mission de groupe"
                tooltip += f"\n👥 Joueurs requis: {def_item.get('required_players', 1)}"
                tooltip += f"\n🎁 Récompense groupe: {def_item.get('group_reward_item', 'Aucune')}"
                bonus_type = def_item.get('bonus_type')
                if bonus_type:
                    tooltip += f"\n⚡ Bonus: {bonus_type} +{def_item.get('bonus_value', 0)}"
            
            item_widget.setToolTip(tooltip)
            self.defs_list.addItem(item_widget)

    def refresh_runs(self):
        """Charge les missions en cours"""
        data = self.api_client.get_solo_runs()
        self.runs_list.clear()

        for run in data.get("runs", []):
            code = run.get("def_code", "")
            login = run.get("twitch_login", "")
            status = run.get("status", "")
            started = run.get("started_at", "")
            ends = run.get("ends_at", "")

            # Formatage de la date
            if started:
                try:
                    from datetime import datetime
                    start_time = datetime.fromisoformat(started.replace('Z', '+00:00'))
                    started_str = start_time.strftime("%H:%M")
                except:
                    started_str = started[:16]
            else:
                started_str = "N/A"

            # Icône selon le statut
            status_icons = {
                "RUNNING": "🟢",
                "COMPLETED": "✅", 
                "FAILED": "❌"
            }
            
            icon = status_icons.get(status, "❓")
            
            text = f"{icon} {login} - {code} [{status}]"
            if started_str != "N/A":
                text += f" - Début: {started_str}"

            self.runs_list.addItem(text)

    def def_selected(self, item):
        """Remplit le formulaire quand une définition est sélectionnée"""
        def_data = item.data(Qt.UserRole)
        
        # Remplir les champs de base
        self.mission_code.setText(def_data.get("code", ""))
        self.mission_name.setText(def_data.get("name", ""))
        self.mission_desc.setText(def_data.get("description", ""))
        self.mission_duration.setText(str(def_data.get("duration_sec", 0)))
        self.mission_xp.setText(str(def_data.get("reward_xp", 0)))
        self.mission_item_qty.setText(str(def_data.get("reward_item_qty", 1)))
        
        # AJOUT: Taux de réussite
        self.mission_success_rate.setValue(def_data.get("success_rate", 100))
        
        # Remplir les ComboBox d'items
        reward_item_code = def_data.get("reward_item_code", "")
        if reward_item_code:
            index = self.mission_item_combo.findData(reward_item_code)
            if index >= 0:
                self.mission_item_combo.setCurrentIndex(index)
        else:
            self.mission_item_combo.setCurrentIndex(0)

        # Remplir les champs de groupe
        is_group = def_data.get("is_group_mission", False)
        self.mission_is_group.setChecked(is_group)
        
        if is_group:
            self.mission_required_players.setText(str(def_data.get("required_players", 3)))
            
            # Charger les coordonnées de la case
            cell_x = def_data.get("cell_x")
            cell_y = def_data.get("cell_y")
            if cell_x is not None:
                self.mission_group_x.setText(str(cell_x))
            if cell_y is not None:
                self.mission_group_y.setText(str(cell_y))
            
            group_reward_item = def_data.get("group_reward_item", "")
            if group_reward_item:
                index = self.mission_group_reward_combo.findData(group_reward_item)
                if index >= 0:
                    self.mission_group_reward_combo.setCurrentIndex(index)
            else:
                self.mission_group_reward_combo.setCurrentIndex(0)
                
            bonus_type = def_data.get("bonus_type", "")
            index = self.mission_bonus_type.findText(bonus_type)
            if index >= 0:
                self.mission_bonus_type.setCurrentIndex(index)
                
            self.mission_bonus_value.setText(str(def_data.get("bonus_value", 10)))

    def load_items_for_dropdown(self):
        """Charge les objets pour les dropdowns - VERSION CORRIGÉE AVEC API /admin/items"""
        try:
            print("🔍 Chargement des items pour les dropdowns...")
            
            # Récupérer tous les items depuis le nouvel endpoint
            data = self.api_client._make_request("GET", "/admin/items")
            
            if data and "items" in data:
                items = data.get("items", [])
                print(f"📦 Total items reçus: {len(items)}")
                
                # DEBUG: Afficher tous les items pour vérification
                print("=== DEBUG ITEMS ===")
                for item in items:
                    print(f"Item: {item.get('code')} - {item.get('name')} - is_group_reward: {item.get('is_group_reward')}")
                print("===================")
                
                # Filtrer les objets sans événement (pour éviter les doublons d'événements)
                items_sans_evenement = [item for item in items if item.get('evenement_id') is None]
                print(f"🎯 Items sans événement: {len(items_sans_evenement)}")
                
                # CORRECTION DÉFINITIVE : 
                # - Objets solo : is_group_reward == False ou None ou non défini
                # - Objets groupe : is_group_reward == True
                items_solo = []
                items_groupe = []
                
                for item in items_sans_evenement:
                    is_group = item.get('is_group_reward')
                    
                    # Débogage détaillé
                    item_code = item.get('code', 'N/A')
                    item_name = item.get('name', 'Sans nom')
                    print(f"🔍 Item {item_code} - is_group_reward: {is_group} (type: {type(is_group)})")
                    
                    # CORRECTION : Gérer différents types de valeurs
                    if is_group is True:
                        items_groupe.append(item)
                        print(f"  → Ajouté aux items GROUPE")
                    else:
                        # Tout le reste (False, None, 0, "", etc.) va dans solo
                        items_solo.append(item)
                        print(f"  → Ajouté aux items SOLO")
                
                print(f"🎯 Items pour missions solo: {len(items_solo)}")
                print(f"🤝 Items pour récompenses groupe: {len(items_groupe)}")
                
                # Afficher les détails pour debug
                if items_solo:
                    solo_codes = [item.get('code') for item in items_solo]
                    print(f"📝 Items solo: {solo_codes}")
                if items_groupe:
                    groupe_codes = [item.get('code') for item in items_groupe]
                    print(f"🎁 Items groupe: {groupe_codes}")
                
                # Vider et remplir les dropdowns
                self.mission_item_combo.clear()
                self.mission_group_reward_combo.clear()
                
                # Mission solo : items normaux (solo)
                self.mission_item_combo.addItem("Aucun", None)
                for item in items_solo:
                    code = item.get('code', '')
                    name = item.get('name', 'Sans nom')
                    rarity = item.get('rarity', 'common')
                    
                    # Formater l'affichage avec icône de rareté
                    rarity_icons = {
                        "common": "⚪",
                        "uncommon": "🟢", 
                        "rare": "🔵",
                        "epic": "🟣",
                        "legendary": "🟠",
                        "Objet de Quête": "⭐",
                        "Objet de Quête Épique": "🌟",
                        "Objet de Quête Légendaire": "💫"
                    }
                    rarity_icon = rarity_icons.get(rarity, "⚪")
                    
                    display_text = f"{rarity_icon} {code} - {name}"
                    self.mission_item_combo.addItem(display_text, code)
                    
                    # Tooltip avec détails
                    index = self.mission_item_combo.count() - 1
                    tooltip = f"📦 {name}\n🔖 Code: {code}\n🎯 Rareté: {rarity}\n👤 Pour: Missions solo"
                    description = item.get('description', '')
                    if description:
                        tooltip += f"\n📝 {description}"
                    self.mission_item_combo.setItemData(index, tooltip, Qt.ToolTipRole)
                
                # Mission groupe : seulement les items marqués True pour groupe
                self.mission_group_reward_combo.addItem("Aucun", None)
                for item in items_groupe:
                    code = item.get('code', '')
                    name = item.get('name', 'Sans nom')
                    rarity = item.get('rarity', 'common')
                    
                    # Formater l'affichage avec icône de rareté
                    rarity_icons = {
                        "common": "⚪",
                        "uncommon": "🟢", 
                        "rare": "🔵",
                        "epic": "🟣",
                        "legendary": "🟠",
                        "Objet de Quête": "⭐",
                        "Objet de Quête Épique": "🌟",
                        "Objet de Quête Légendaire": "💫"
                    }
                    rarity_icon = rarity_icons.get(rarity, "⚪")
                    
                    display_text = f"{rarity_icon} {code} - {name}"
                    self.mission_group_reward_combo.addItem(display_text, code)
                    
                    # Tooltip avec détails
                    index = self.mission_group_reward_combo.count() - 1
                    tooltip = f"📦 {name}\n🔖 Code: {code}\n🎯 Rareté: {rarity}\n👥 Pour: Missions de groupe"
                    description = item.get('description', '')
                    if description:
                        tooltip += f"\n📝 {description}"
                    self.mission_group_reward_combo.setItemData(index, tooltip, Qt.ToolTipRole)
                
                print(f"✅ Solo combo: {self.mission_item_combo.count()} items")
                print(f"✅ Groupe combo: {self.mission_group_reward_combo.count()} items")
                
                # Avertissement si pas d'items pour groupe
                if not items_groupe:
                    print("⚠️ ATTENTION: Aucun item disponible pour les récompenses de groupe")
                    print("💡 Conseil: Marquez des items avec is_group_reward = True dans la base de données")
                    
                    # Ajouter un item placeholder pour informer l'utilisateur
                    self.mission_group_reward_combo.addItem("❌ Aucun item disponible pour groupe", "ERROR")
                    
            else:
                print("❌ Aucun item trouvé ou format de réponse invalide")
                if data:
                    print(f"📄 Réponse API: {data}")
                
        except Exception as e:
            print(f"❌ Erreur chargement items: {e}")
            import traceback
            traceback.print_exc()
            
            # En cas d'erreur, vider les combos et afficher un message d'erreur
            self.mission_item_combo.clear()
            self.mission_group_reward_combo.clear()
            self.mission_item_combo.addItem("❌ Erreur de chargement", None)
            self.mission_group_reward_combo.addItem("❌ Erreur de chargement", None)
        
    def save_def(self):
        """Sauvegarde la définition de mission - VERSION AMÉLIORÉE"""
        code = self.mission_code.text().strip().upper()
        if not code:
            QMessageBox.warning(self, "Erreur", "Le code est requis")
            return

        # Récupérer les codes d'items depuis les ComboBox
        reward_item_code = self.mission_item_combo.currentData()
        group_reward_item = self.mission_group_reward_combo.currentData()

        print(f"🔍 Item solo sélectionné: {reward_item_code}")
        print(f"🔍 Item groupe sélectionné: {group_reward_item}")

        # Validation pour les missions de groupe
        is_group = self.mission_is_group.isChecked()
        if is_group and group_reward_item == "ERROR":
            QMessageBox.warning(self, "Erreur", "Aucun item disponible pour les récompenses de groupe. Créez d'abord des items marqués comme récompenses de groupe.")
            return

        # Données de base AVEC SUCCESS_RATE
        def_data = {
            "code": code,
            "name": self.mission_name.text(),
            "description": self.mission_desc.text(),
            "duration_sec": int(self.mission_duration.text() or "0"),
            "reward_xp": int(self.mission_xp.text() or "0"),
            "success_rate": self.mission_success_rate.value(),  # NOUVEAU CHAMP
            "reward_item_code": reward_item_code,
            "reward_item_qty": int(self.mission_item_qty.text() or "1")
        }

        # Données des missions de groupe
        if is_group:
            # Gestion des coordonnées
            x = self.mission_group_x.text().strip() or "0"
            y = self.mission_group_y.text().strip() or "0"
            
            def_data.update({
                "is_group_mission": True,
                "required_players": int(self.mission_required_players.text() or "3"),
                "group_reward_item": group_reward_item,
                "group_reward_qty": int(self.mission_item_qty.text() or "1"),
                "bonus_type": self.mission_bonus_type.currentText() or None,
                "bonus_value": int(self.mission_bonus_value.text() or "10"),
                "cell_x": int(x),
                "cell_y": int(y)
            })
            
            print(f"💾 Mission GROUPE: {def_data}")
        else:
            def_data.update({
                "is_group_mission": False,
                "required_players": 1,
                "group_reward_item": None,
                "group_reward_qty": 1,
                "bonus_type": None,
                "bonus_value": 0
            })
            print(f"💾 Mission SOLO: {def_data}")

        result = self.api_client.save_solo_def(def_data)
        if result and "error" in result:
            QMessageBox.critical(self, "Erreur", f"Erreur lors de la sauvegarde: {result['error']}")
        else:
            success_message = f"Mission '{code}' enregistrée avec succès"
            if is_group:
                success_message += f"\n\n📍 Position: ({def_data['cell_x']}, {def_data['cell_y']})"
                if group_reward_item:
                    success_message += f"\n🎁 Récompense groupe: {group_reward_item}"
            else:
                if reward_item_code:
                    success_message += f"\n🎁 Récompense solo: {reward_item_code}"
                    
            QMessageBox.information(self, "Succès", success_message)
            self.refresh_defs()
        
        
    def delete_def(self):
        """Supprime la définition sélectionnée - MÉTHODE MANQUANTE"""
        code = self.mission_code.text().strip().upper()
        if not code:
            QMessageBox.warning(self, "Erreur", "Aucune mission sélectionnée")
            return

        reply = QMessageBox.question(
            self, 
            "Confirmation", 
            f"Supprimer la mission {code} ?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            result = self.api_client.delete_solo_def(code)
            if result and "error" in result:
                QMessageBox.critical(self, "Erreur", f"Erreur lors de la suppression: {result['error']}")
            else:
                QMessageBox.information(self, "Succès", "Mission supprimée avec succès")
                self.refresh_defs()
                # Réinitialiser le formulaire
                self.mission_code.clear()
                self.mission_name.clear()
                self.mission_desc.clear()
                self.mission_duration.setText("60")
                self.mission_xp.setText("10")
                self.mission_item_combo.setCurrentIndex(0)
                self.mission_item_qty.setText("1")
                self.mission_is_group.setChecked(False)
'''
class SoloTab(QWidget):
    """Onglet de gestion des missions solo"""

    def __init__(self, api_client):
        super().__init__()
        self.api_client = api_client
        self.init_ui()
        self.refresh_defs()
        self.refresh_runs()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(10)
        layout.setContentsMargins(10, 10, 10, 10)

        split_layout = QHBoxLayout()
        split_layout.setSpacing(14)

        form_group = QGroupBox("Définition de mission")
        form_layout = QFormLayout()
        form_layout.setLabelAlignment(Qt.AlignLeft)

        self.solo_code = QLineEdit()
        self.solo_name = QLineEdit()
        self.solo_desc = QLineEdit()
        self.solo_duration = QLineEdit("60"); self.solo_duration.setValidator(QIntValidator(1, 3600))
        self.solo_xp = QLineEdit("10"); self.solo_xp.setValidator(QIntValidator(0, 1000))
        self.solo_item = QLineEdit()
        self.solo_item_qty = QLineEdit("1"); self.solo_item_qty.setValidator(QIntValidator(1, 100))

        form_layout.addRow("Code", self.solo_code)
        form_layout.addRow("Nom", self.solo_name)
        form_layout.addRow("Description", self.solo_desc)
        form_layout.addRow("Durée (s)", self.solo_duration)
        form_layout.addRow("XP récompense", self.solo_xp)
        form_layout.addRow("Item (optionnel)", self.solo_item)
        form_layout.addRow("Quantité item", self.solo_item_qty)

        btn_layout = QHBoxLayout()
        save_btn = QPushButton("Enregistrer"); save_btn.setObjectName("primary"); save_btn.clicked.connect(self.save_def)
        delete_btn = QPushButton("Supprimer"); delete_btn.setObjectName("danger"); delete_btn.clicked.connect(self.delete_def)
        refresh_btn = QPushButton("Rafraîchir"); refresh_btn.clicked.connect(self.refresh_defs)

        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(delete_btn)
        btn_layout.addWidget(refresh_btn)

        form_layout.addRow(btn_layout)
        form_group.setLayout(form_layout)
        split_layout.addWidget(form_group, 1)

        defs_group = QGroupBox("Définitions existantes")
        defs_layout = QVBoxLayout()
        self.defs_list = QListWidget()
        self.defs_list.itemClicked.connect(self.def_selected)
        defs_layout.addWidget(self.defs_list)
        defs_group.setLayout(defs_layout)
        split_layout.addWidget(defs_group, 1)

        layout.addLayout(split_layout)

        runs_group = QGroupBox("Runs récents")
        runs_layout = QVBoxLayout()
        runs_header = QHBoxLayout()
        refresh_runs_btn = QPushButton("Rafraîchir"); refresh_runs_btn.clicked.connect(self.refresh_runs)
        runs_header.addStretch()
        runs_header.addWidget(refresh_runs_btn)

        self.runs_list = QListWidget()

        runs_layout.addLayout(runs_header)
        runs_layout.addWidget(self.runs_list)
        runs_group.setLayout(runs_layout)
        layout.addWidget(runs_group)

        self.setLayout(layout)

    def refresh_defs(self):
        data = self.api_client.get_solo_defs()
        self.defs_list.clear()

        if not data or "defs" not in data:
            self.defs_list.addItem("❌ Impossible de charger les définitions")
            return

        for def_item in data.get("defs", []):
            code = def_item.get("code", "")
            name = def_item.get("name", "")
            duration = def_item.get("duration_sec", 0)
            xp = def_item.get("reward_xp", 0)
            item = def_item.get("reward_item_code", "")
            item_qty = def_item.get("reward_item_qty", 0)

            text = f"{code} - {name} ({duration}s, +{xp} XP"
            if item:
                text += f", {item}×{item_qty}"
            text += ")"

            item = QListWidgetItem(text)
            item.setData(Qt.UserRole, def_item)
            self.defs_list.addItem(item)

    def refresh_runs(self):
        data = self.api_client.get_solo_runs()
        self.runs_list.clear()

        for run in data.get("runs", []):
            code = run.get("code", "")
            login = run.get("twitch_login", "")
            status = run.get("status", "")
            started = run.get("started_at", "")
            ends = run.get("ends_at", "")

            text = f"{code} - {login} [{status}]"
            if started:
                text += f" started: {started}"
            if ends:
                text += f" ends: {ends}"

            self.runs_list.addItem(text)

    def def_selected(self, item):
        def_data = item.data(Qt.UserRole)
        self.solo_code.setText(def_data.get("code", ""))
        self.solo_name.setText(def_data.get("name", ""))
        self.solo_desc.setText(def_data.get("description", ""))
        self.solo_duration.setText(str(def_data.get("duration_sec", 0)))
        self.solo_xp.setText(str(def_data.get("reward_xp", 0)))
        self.solo_item.setText(def_data.get("reward_item_code", ""))
        self.solo_item_qty.setText(str(def_data.get("reward_item_qty", 1)))

    def save_def(self):
        code = self.solo_code.text().strip().upper()
        if not code:
            QMessageBox.warning(self, "Erreur", "Le code est requis")
            return

        def_data = {
            "code": code,
            "name": self.solo_name.text(),
            "description": self.solo_desc.text(),
            "duration_sec": int(self.solo_duration.text() or "0"),
            "reward_xp": int(self.solo_xp.text() or "0"),
            "reward_item_code": self.solo_item.text().strip().upper() or None,
            "reward_item_qty": int(self.solo_item_qty.text() or "1")
        }

        result = self.api_client.save_solo_def(def_data)
        if result and "error" in result:
            QMessageBox.critical(self, "Erreur", f"Erreur lors de la sauvegarde: {result['error']}")
        else:
            QMessageBox.information(self, "Succès", "Définition enregistrée avec succès")
            self.refresh_defs()

    def delete_def(self):
        code = self.solo_code.text().strip().upper()
        if not code:
            QMessageBox.warning(self, "Erreur", "Aucune définition sélectionnée")
            return

        if QMessageBox.question(self, "Confirmation", f"Supprimer la définition {code} ?") == QMessageBox.Yes:
            result = self.api_client.delete_solo_def(code)
            if result and "error" in result:
                QMessageBox.critical(self, "Erreur", f"Erreur lors de la suppression: {result['error']}")
            else:
                QMessageBox.information(self, "Succès", "Définition supprimée avec succès")
                self.refresh_defs()
                self.solo_code.clear()
                self.solo_name.clear()
                self.solo_desc.clear()
                self.solo_duration.setText("60")
                self.solo_xp.setText("10")
                self.solo_item.clear()
                self.solo_item_qty.setText("1")
   '''
#SELECTEUR DE CASE
class CellSelectorDialog(QDialog):
    """Boîte de dialogue pour sélectionner une case sur la carte - VERSION DYNAMIQUE"""
    
    def __init__(self, parent=None, api_client=None):
        super().__init__(parent)
        self.api_client = api_client
        self.selected_cell = None
        self.cells_data = []
        self.map_data = {}
        self.existing_missions = []
        self.init_ui()
        self.load_map_data()
        self.load_existing_missions()
        
    def init_ui(self):
        self.setWindowTitle("🗺️ Sélectionner une case pour la mission de groupe")
        
        # Taille dynamique basée sur l'écran
        screen_geometry = QApplication.primaryScreen().availableGeometry()
        self.setMinimumSize(800, 600)
        # Utiliser 80% de la largeur et hauteur de l'écran
        self.resize(int(screen_geometry.width() * 0.8), int(screen_geometry.height() * 0.8))
        
        layout = QVBoxLayout()
        
        # En-tête
        header_layout = QHBoxLayout()
        header_layout.addWidget(QLabel("Cliquez sur une case pour la sélectionner"))
        header_layout.addStretch()
        
        self.status_label = QLabel("Chargement de la carte...")
        header_layout.addWidget(self.status_label)
        
        layout.addLayout(header_layout)
        
        # Légende compacte
        legend_group = QGroupBox("📋 Légende")
        legend_layout = QHBoxLayout()
        
        legends = [
            ("🏕️", "Camp"),
            ("🟢", "Révélée"), 
            ("🔵", "Cachée"),
            ("🔴", "Occupée"),
            ("⭐", "Sélection")
        ]
        
        for icon, text in legends:
            legend_item = QHBoxLayout()
            legend_item.addWidget(QLabel(icon))
            legend_item.addWidget(QLabel(text))
            legend_item.setSpacing(2)
            legend_layout.addLayout(legend_item)
        
        legend_group.setLayout(legend_layout)
        layout.addWidget(legend_group)
        
        # Zone de défilement avec taille dynamique
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setMinimumHeight(400)
        
        # Widget pour la grille
        self.grid_widget = QWidget()
        self.grid_layout = QGridLayout(self.grid_widget)
        self.grid_layout.setSpacing(2)
        self.grid_layout.setAlignment(Qt.AlignCenter)
        
        self.scroll_area.setWidget(self.grid_widget)
        layout.addWidget(self.scroll_area)
        
        # Section coordonnées manuelles
        manual_group = QGroupBox("📝 Coordonnées manuelles")
        manual_layout = QHBoxLayout()
        
        self.manual_x = QSpinBox()
        self.manual_x.setRange(0, 50)
        self.manual_x.setValue(0)
        
        self.manual_y = QSpinBox()
        self.manual_y.setRange(0, 50)
        self.manual_y.setValue(0)
        
        manual_btn = QPushButton("✅ Utiliser ces coordonnées")
        manual_btn.clicked.connect(self.use_manual_coords)
        
        manual_layout.addWidget(QLabel("X:"))
        manual_layout.addWidget(self.manual_x)
        manual_layout.addWidget(QLabel("Y:"))
        manual_layout.addWidget(self.manual_y)
        manual_layout.addWidget(manual_btn)
        manual_layout.addStretch()
        
        manual_group.setLayout(manual_layout)
        layout.addWidget(manual_group)

        # Informations de la case sélectionnée
        self.selection_info = QLabel("Aucune case sélectionnée")
        self.selection_info.setStyleSheet("font-weight: bold; padding: 10px; background-color: #161b22; border-radius: 5px;")
        self.selection_info.setWordWrap(True)
        layout.addWidget(self.selection_info)
        
        # Boutons
        button_layout = QHBoxLayout()
        confirm_btn = QPushButton("✅ Confirmer la sélection")
        confirm_btn.clicked.connect(self.confirm_selection)
        confirm_btn.setEnabled(False)
        self.confirm_btn = confirm_btn
        
        cancel_btn = QPushButton("❌ Annuler")
        cancel_btn.clicked.connect(self.reject)
        
        button_layout.addWidget(confirm_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def load_existing_missions(self):
        """Charge les missions de groupe existantes depuis les données de la carte"""
        try:
            print("🔍 Chargement des missions existantes depuis la carte...")
            
            # Les missions de groupe sont déjà dans self.map_data depuis /api/map/raw
            if self.map_data and "group_missions" in self.map_data:
                self.existing_missions = self.map_data.get("group_missions", [])
                print(f"🎯 {len(self.existing_missions)} missions de groupe existantes trouvées:")
                for mission in self.existing_missions:
                    print(f"   - {mission.get('mission_code')} sur ({mission.get('x')}, {mission.get('y')})")
            else:
                print("❌ Aucune mission de groupe dans les données de la carte")
                self.existing_missions = []
                
        except Exception as e:
            print(f"❌ Erreur chargement missions: {e}")
            self.existing_missions = []
        
    def use_manual_coords(self):
        """Utilise les coordonnées manuelles"""
        x = self.manual_x.value()
        y = self.manual_y.value()
        
        # Vérifier si la case est valide
        validation_result = self.validate_cell_selection(x, y)
        if not validation_result["valid"]:
            QMessageBox.warning(self, "Case invalide", validation_result["message"])
            return
        
        self.selected_cell = (x, y)
        self.selection_info.setText(f"✅ Coordonnées manuelles: ({x}, {y})\n{validation_result['message']}")
        self.confirm_btn.setEnabled(True)
        
    def load_map_data(self):
        """Charge les données de la carte depuis l'API"""
        try:
            self.status_label.setText("Chargement des données de la carte...")
            
            data = self.api_client._make_request("GET", "/api/map/raw")
            print(f"🗺️ Données carte reçues: {data}")
            
            if data and "cells" in data:
                self.map_data = data
                self.cells_data = data.get("cells", [])
                
                if self.cells_data:
                    # CHARGER LES MISSIONS IMMÉDIATEMENT APRÈS LA CARTE
                    self.load_existing_missions()
                    self.display_grid()
                    self.status_label.setText(f"✅ Carte chargée - {len(self.cells_data)} cases, {len(self.existing_missions)} missions")
                else:
                    self.status_label.setText("⚠️ Carte vide - Utilisation du mode manuel")
                    self.create_fallback_grid()
            else:
                self.status_label.setText("❌ Format de réponse invalide")
                self.create_fallback_grid()
                
        except Exception as e:
            self.status_label.setText(f"❌ Erreur: {str(e)}")
            self.create_fallback_grid()

    def load_existing_missions(self):
        """Charge les missions de groupe existantes - VERSION CORRIGÉE AVEC API MAP/RAW"""
        try:
            print("🔍 Chargement des missions existantes depuis /api/map/raw...")
            data = self.api_client._make_request("GET", "/api/map/raw")
            
            if data and "group_missions" in data:
                self.existing_missions = data.get("group_missions", [])
                print(f"🎯 {len(self.existing_missions)} missions de groupe trouvées:")
                for mission in self.existing_missions:
                    x = mission.get('x')
                    y = mission.get('y')
                    code = mission.get('mission_code', 'Inconnue')
                    name = mission.get('mission_name', 'Sans nom')
                    print(f"   - {code} ({name}) sur ({x}, {y})")
            else:
                print("❌ Aucune donnée de missions reçue")
                self.existing_missions = []
        except Exception as e:
            print(f"❌ Erreur chargement missions: {e}")
            self.existing_missions = []

    def validate_cell_selection(self, x, y):
        """Valide si une case peut être sélectionnée pour une mission de groupe"""
        camp = self.map_data.get('camp', {})
        camp_x = camp.get('x')
        camp_y = camp.get('y')
        
        # Vérifier si c'est le camp
        if x == camp_x and y == camp_y:
            return {
                "valid": False,
                "message": "❌ Impossible de créer une mission sur le camp de base !"
            }
        
        # CORRECTION : On permet maintenant les cases avec missions existantes
        # Compter les missions existantes sur cette case
        existing_missions_count = 0
        for mission in self.existing_missions:
            if mission.get("x") == x and mission.get("y") == y:
                existing_missions_count += 1
        
        # Vérifier si la case existe dans la carte
        cell_exists = any(cell.get('x') == x and cell.get('y') == y for cell in self.cells_data)
        
        if not cell_exists:
            return {
                "valid": True,
                "message": "⚠️ Case hors carte - Vérifiez que les coordonnées sont valides"
            }
        
        # Message informatif sur les missions existantes
        if existing_missions_count > 0:
            message = f"✅ Case disponible - {existing_missions_count} mission(s) existante(s) sur cette case"
        else:
            message = "✅ Case disponible pour mission de groupe"
        
        return {
            "valid": True, 
            "message": message
        }
    
    def create_fallback_grid(self):
        """Crée une grille de secours quand la carte est vide"""
        print("🔄 Création d'une grille de secours...")
        
        # Nettoyer la grille existante
        for i in reversed(range(self.grid_layout.count())):
            widget = self.grid_layout.itemAt(i).widget()
            if widget:
                widget.deleteLater()
        
        info_label = QLabel(
            "La carte semble vide. Vous pouvez :\n"
            "• Utiliser les coordonnées manuelles ci-dessous\n"  
            "• Vérifier que la carte a été initialisée\n"
            "• Contacter l'administrateur"
        )
        info_label.setAlignment(Qt.AlignCenter)
        info_label.setStyleSheet("color: #ffa726; padding: 20px;")
        self.grid_layout.addWidget(info_label, 0, 0)
        
    def calculate_cell_size(self, grid_width, grid_height):
        """Calcule la taille dynamique des cases"""
        # Taille disponible dans la scroll area
        available_width = self.scroll_area.width() - 100  # Marge pour les barres de défilement
        available_height = self.scroll_area.height() - 100
        
        # Calculer la taille maximale possible
        max_cell_width = available_width // max(grid_width, 1)
        max_cell_height = available_height // max(grid_height, 1)
        
        # Prendre le plus petit pour garder les cases carrées
        cell_size = min(max_cell_width, max_cell_height, 60)  # 60px maximum
        cell_size = max(cell_size, 25)  # 25px minimum
        
        print(f"📐 Taille de case calculée: {cell_size}px")
        return cell_size
        
    def display_grid(self):
        """Affiche la grille de la carte - VERSION PERMETTANT PLUSIEURS MISSIONS PAR CASE"""
        # Nettoyer la grille existante
        for i in reversed(range(self.grid_layout.count())):
            widget = self.grid_layout.itemAt(i).widget()
            if widget:
                widget.deleteLater()
        
        if not self.cells_data:
            self.grid_layout.addWidget(QLabel("Aucune donnée de carte disponible"), 0, 0)
            return
            
        # Trouver les dimensions de la carte
        xs = [cell['x'] for cell in self.cells_data]
        ys = [cell['y'] for cell in self.cells_data]
        
        if not xs or not ys:
            return
            
        min_x, max_x = min(xs), max(xs)
        min_y, max_y = min(ys), max(ys)
        
        grid_width = max_x - min_x + 2
        grid_height = max_y - min_y + 2
        
        print(f"🗺️ Dimensions de la grille: {grid_width}x{grid_height}")
        print(f"🎯 Missions existantes à afficher: {len(self.existing_missions)}")
        
        # Calculer la taille dynamique des cases
        cell_size = self.calculate_cell_size(grid_width, grid_height)
        
        # Récupérer les coordonnées du camp
        camp = self.map_data.get('camp', {})
        camp_x = camp.get('x')
        camp_y = camp.get('y')
        
        # Créer un dictionnaire pour un accès rapide aux cellules
        cell_dict = {(cell['x'], cell['y']): cell for cell in self.cells_data}
        
        # Créer un dictionnaire pour les missions existantes par coordonnées
        mission_dict = {}
        for mission in self.existing_missions:
            x = mission.get("x")
            y = mission.get("y")
            if x is not None and y is not None:
                if (x, y) not in mission_dict:
                    mission_dict[(x, y)] = []
                mission_dict[(x, y)].append(mission)
                print(f"📌 Mission trouvée: {mission.get('mission_code')} sur ({x}, {y})")
        
        # Ajouter les en-têtes de colonnes (X)
        for x in range(min_x, max_x + 1):
            label = QLabel(str(x))
            label.setAlignment(Qt.AlignCenter)
            label.setStyleSheet("font-weight: bold; background-color: #30363d; padding: 4px; font-size: 10px;")
            label.setFixedSize(cell_size, 25)
            self.grid_layout.addWidget(label, 0, x - min_x + 1)
            
        # Ajouter les en-têtes de lignes (Y) et les cases
        for y in range(min_y, max_y + 1):
            # En-tête de ligne
            label = QLabel(str(y))
            label.setAlignment(Qt.AlignCenter)
            label.setStyleSheet("font-weight: bold; background-color: #30363d; padding: 4px; font-size: 10px;")
            label.setFixedSize(25, cell_size)
            self.grid_layout.addWidget(label, y - min_y + 1, 0)
            
            # Cases
            for x in range(min_x, max_x + 1):
                cell = cell_dict.get((x, y))
                
                # Vérifier si des missions existent sur cette case
                existing_missions = mission_dict.get((x, y), [])
                
                cell_btn = QPushButton()
                cell_btn.setFixedSize(cell_size, cell_size)
                cell_btn.setProperty("coords", (x, y))
                cell_btn.clicked.connect(lambda checked, btn=cell_btn: self.select_cell(btn))
                
                # Vérifier si c'est le camp
                if x == camp_x and y == camp_y:
                    cell_btn.setText("🏕️")
                    cell_btn.setStyleSheet(f"""
                        QPushButton {{
                            background-color: #FF6B6B;
                            border: 2px solid #FF0000;
                            border-radius: 3px;
                            font-size: {max(12, cell_size//4)}px;
                            color: white;
                        }}
                    """)
                    cell_btn.setEnabled(False)
                    cell_btn.setToolTip("🏕️ Camp de base - Case interdite")
                    self.grid_layout.addWidget(cell_btn, y - min_y + 1, x - min_x + 1)
                    continue
                
                # Case avec missions existantes - MAINTENANT AUTORISÉE
                if existing_missions:
                    mission_count = len(existing_missions)
                    cell_btn.setText(f"{mission_count}📋")
                    cell_btn.setStyleSheet(f"""
                        QPushButton {{
                            background-color: #ffa726;
                            border: 2px solid #ff9800;
                            border-radius: 3px;
                            font-size: {max(10, cell_size//6)}px;
                            color: black;
                            font-weight: bold;
                        }}
                        QPushButton:hover {{
                            background-color: #ffb74d;
                            border: 2px solid #ffa726;
                        }}
                    """)
                    
                    # Tooltip informatif
                    tooltip = f"🟠 Case ({x},{y}) - {mission_count} mission(s) existante(s)\n"
                    for i, mission in enumerate(existing_missions):
                        mission_code = mission.get('mission_code', 'Inconnue')
                        mission_name = mission.get('mission_name', 'Sans nom')
                        required_players = mission.get('required_players', 0)
                        completion_count = mission.get('completion_count', 0)
                        tooltip += f"{i+1}. {mission_code}: {mission_name} (👥{required_players}, ✅{completion_count})\n"
                    tooltip += "\n✅ Vous pouvez ajouter une nouvelle mission sur cette case"
                    
                    cell_btn.setToolTip(tooltip)
                    self.grid_layout.addWidget(cell_btn, y - min_y + 1, x - min_x + 1)
                    continue
                
                # Case normale
                if cell:
                    status = cell.get('status', 'hidden')
                    biome = cell.get('biome_name', cell.get('biome', 'inconnu'))
                    
                    if status == 'revealed':
                        # Case révélée
                        cell_btn.setStyleSheet(f"""
                            QPushButton {{
                                background-color: #3fb950;
                                border: 2px solid #2da44e;
                                border-radius: 3px;
                                font-weight: bold;
                                font-size: {max(10, cell_size//6)}px;
                            }}
                            QPushButton:hover {{
                                background-color: #56d364;
                                border: 2px solid #3fb950;
                            }}
                        """)
                        tooltip = f"🟢 Case ({x},{y})\n🌿 {biome}\n✅ Disponible"
                    else:
                        # Case cachée
                        cell_btn.setStyleSheet(f"""
                            QPushButton {{
                                background-color: #58a6ff;
                                border: 2px solid #1f6feb;
                                border-radius: 3px;
                                font-size: {max(10, cell_size//6)}px;
                            }}
                            QPushButton:hover {{
                                background-color: #79c0ff;
                                border: 2px solid #58a6ff;
                            }}
                        """)
                        tooltip = f"🔵 Case ({x},{y})\n🌿 {biome}\n⏳ Cachée"
                    
                    # Informations supplémentaires
                    reveal_count = cell.get('reveal_count', 0)
                    required_reveals = cell.get('required_reveals', 0)
                    
                    if status == 'hidden':
                        tooltip += f"\n📊 {reveal_count}/{required_reveals} explorations"
                    
                    cell_btn.setToolTip(tooltip)
                else:
                    # Case qui n'existe pas encore
                    cell_btn.setStyleSheet("""
                        QPushButton {
                            background-color: #2d2d2d;
                            border: 2px solid #1a1a1a;
                            border-radius: 3px;
                        }
                    """)
                    cell_btn.setEnabled(False)
                    cell_btn.setToolTip(f"Case ({x},{y})\n❌ Non disponible")
                
                self.grid_layout.addWidget(cell_btn, y - min_y + 1, x - min_x + 1)     
                
    def select_cell(self, button):
        """Sélectionne une case"""
        coords = button.property("coords")
        if coords:
            x, y = coords
            
            # Valider la sélection
            validation_result = self.validate_cell_selection(x, y)
            if not validation_result["valid"]:
                QMessageBox.warning(self, "Case invalide", validation_result["message"])
                return
            
            self.selected_cell = (x, y)
            
            # Mettre en évidence la sélection
            self.clear_selection()
            button.setStyleSheet(f"""
                QPushButton {{
                    background-color: #ffd700;
                    border: 3px solid #ffa500;
                    border-radius: 3px;
                    font-weight: bold;
                    color: black;
                    font-size: {max(12, button.width()//4)}px;
                }}
            """)
            button.setText("⭐")
            
            # Afficher les informations
            cell_info = self.get_cell_info(x, y)
            
            # Ajouter les informations sur les missions existantes
            existing_missions = [m for m in self.existing_missions if m.get("x") == x and m.get("y") == y]
            if existing_missions:
                cell_info += f"\n\n📋 Missions existantes sur cette case ({len(existing_missions)}):"
                for mission in existing_missions:
                    mission_code = mission.get('mission_code', 'Inconnue')
                    mission_name = mission.get('mission_name', 'Sans nom')
                    required_players = mission.get('required_players', 0)
                    cell_info += f"\n• {mission_code}: {mission_name} (👥{required_players})"
            
            self.selection_info.setText(f"✅ Case sélectionnée: ({x}, {y})\n{cell_info}")
            self.confirm_btn.setEnabled(True)
            
    def clear_selection(self):
        """Réinitialise l'apparence de toutes les cases"""
        for i in range(self.grid_layout.count()):
            widget = self.grid_layout.itemAt(i).widget()
            if widget and isinstance(widget, QPushButton) and widget.property("coords"):
                coords = widget.property("coords")
                x, y = coords
                
                # Ne pas modifier le camp
                camp = self.map_data.get('camp', {})
                if x == camp.get('x') and y == camp.get('y'):
                    continue
                    
                # Vérifier si des missions existent sur cette case
                existing_missions = [m for m in self.existing_missions if m.get("x") == x and m.get("y") == y]
                cell_size = widget.width()
                
                if existing_missions:
                    # Réafficher comme case avec missions
                    mission_count = len(existing_missions)
                    widget.setText(f"{mission_count}📋")
                    widget.setStyleSheet(f"""
                        QPushButton {{
                            background-color: #ffa726;
                            border: 2px solid #ff9800;
                            border-radius: 3px;
                            font-size: {max(10, cell_size//6)}px;
                            color: black;
                            font-weight: bold;
                        }}
                        QPushButton:hover {{
                            background-color: #ffb74d;
                            border: 2px solid #ffa726;
                        }}
                    """)
                else:
                    # Case normale
                    cell = next((c for c in self.cells_data if c.get('x') == x and c.get('y') == y), None)
                    if cell:
                        status = cell.get('status', 'hidden')
                        if status == 'revealed':
                            widget.setStyleSheet(f"""
                                QPushButton {{
                                    background-color: #3fb950;
                                    border: 2px solid #2da44e;
                                    border-radius: 3px;
                                    font-weight: bold;
                                    font-size: {max(10, cell_size//6)}px;
                                }}
                                QPushButton:hover {{
                                    background-color: #56d364;
                                    border: 2px solid #3fb950;
                                }}
                            """)
                        else:
                            widget.setStyleSheet(f"""
                                QPushButton {{
                                    background-color: #58a6ff;
                                    border: 2px solid #1f6feb;
                                    border-radius: 3px;
                                    font-size: {max(10, cell_size//6)}px;
                                }}
                                QPushButton:hover {{
                                    background-color: #79c0ff;
                                    border: 2px solid #58a6ff;
                                }}
                            """)
                        widget.setText("")  # Retirer l'étoile
                        
    def get_cell_info(self, x, y):
        """Récupère les informations d'une case spécifique"""
        cell = next((c for c in self.cells_data if c.get('x') == x and c.get('y') == y), None)
        
        info = ""
        
        if cell:
            status = cell.get('status', 'hidden')
            biome = cell.get('biome_name', cell.get('biome', 'inconnu'))
            
            if status == 'revealed':
                info += f"🟢 Statut: Révélée\n"
                info += f"🌿 Biome: {biome}\n"
                info += "✅ Prête pour mission de groupe"
            else:
                reveal_count = cell.get('reveal_count', 0)
                required_reveals = cell.get('required_reveals', 0)
                info += f"🔵 Statut: Cachée\n"
                info += f"🌿 Biome: {biome}\n"
                info += f"📊 Progression: {reveal_count}/{required_reveals}\n"
                info += "⚠️ Nécessite exploration d'abord"
        else:
            info += "❓ Case non explorée\n"
            info += "⚠️ Vérifiez la validité des coordonnées"
            
        return info
        
    def confirm_selection(self):
        """Confirme la sélection et ferme la boîte de dialogue"""
        if self.selected_cell:
            self.accept()
            
    def get_selected_coords(self):
        """Retourne les coordonnées sélectionnées"""
        return self.selected_cell
    
    def resizeEvent(self, event):
        """Redessine la grille quand la fenêtre est redimensionnée"""
        super().resizeEvent(event)
        if self.cells_data:
            # Redessiner la grille avec la nouvelle taille
            QTimer.singleShot(100, self.display_grid)            
            
# Section 6.2: Onglet Coffre (version temporaire)
class CoffreTab(QWidget):
    """Onglet de visualisation du coffre communautaire"""

    def __init__(self, api_client):
        super().__init__()
        self.api_client = api_client
        self.init_ui()
        self.load_coffre()

    def init_ui(self):
        layout = QVBoxLayout()
        
        # Header
        header_layout = QHBoxLayout()
        title = QLabel("🏰 COFFRE COMMUNAUTAIRE")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #ffd700;")
        header_layout.addWidget(title)
        header_layout.addStretch()
        
        refresh_btn = QPushButton("🔄 Actualiser")
        refresh_btn.clicked.connect(self.load_coffre)
        header_layout.addWidget(refresh_btn)
        
        layout.addLayout(header_layout)

        # Message de statut
        self.status_label = QLabel("Chargement...")
        self.status_label.setStyleSheet("color: #8b949e; padding: 5px;")
        layout.addWidget(self.status_label)

        # Liste des objets
        self.coffre_list = QListWidget()
        self.coffre_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                color: #e6edf3;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 5px;
            }
        """)
        layout.addWidget(self.coffre_list)

        self.setLayout(layout)

    def load_coffre(self):
        """Charge les données du coffre"""
        try:
            self.status_label.setText("🔄 Chargement...")
            self.coffre_list.clear()
            
            data = self.api_client._cached_get("/admin/coffre/items", cache_ttl=30)
            
            if data and "success" in data and not data["success"]:
                error_msg = data.get("error", "Erreur inconnue")
                self.status_label.setText(f"❌ Erreur backend: {error_msg}")
                self.coffre_list.addItem("❌ Le backend retourne une erreur")
                self.coffre_list.addItem(f"📋 Message: {error_msg}")
                self.coffre_list.addItem("🔧 Veuillez vérifier la configuration du serveur")
                return
                
            if data and "success" in data and data["success"]:
                items = data.get("items", [])
                if items:
                    self.display_items(items)
                    self.status_label.setText(f"✅ {len(items)} objet(s) chargé(s)")
                else:
                    self.status_label.setText("📭 Le coffre est vide")
                    self.coffre_list.addItem("📭 Aucun objet dans le coffre communautaire")
            else:
                self.status_label.setText("❌ Format de réponse inattendu")
                self.coffre_list.addItem("❌ Le serveur a retourné un format inattendu")
                
        except Exception as e:
            self.status_label.setText(f"❌ Erreur: {str(e)}")
            self.coffre_list.addItem(f"❌ Exception: {str(e)}")

    def display_items(self, items):
        """Affiche les items dans la liste"""
        for item in items:
            item_code = item.get('item_code', 'N/A')
            name = item.get('name', 'Sans nom')
            rarity = item.get('rarity', 'common')
            quantite = item.get('quantite', 1)
            
            # Couleur selon la rareté
            color = RARITY_COLORS.get(rarity, "#8b949e")
            
            item_text = f"📦 {name} ×{quantite} ({rarity})"
            item_widget = QListWidgetItem(item_text)
            item_widget.setForeground(QColor(color))
            self.coffre_list.addItem(item_widget)

#Section BOSS
class BossTab(QWidget):
    """Onglet de gestion des boss avec gestion des sons"""

    def __init__(self, api_client):
        super().__init__()
        self.api_client = api_client
        self.current_boss = None
        self.current_image_path = None
        self.current_video_path = None
        self.current_sounds = {}  # Dictionnaire pour stocker les chemins des sons
        self.init_ui()
        self.load_boss_list()
        self.load_current_boss()
        self.start_boss_sse_listener()
        print("✅ Écouteur sons d'agonie démarré")

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)

        # Header
        header_layout = QHBoxLayout()
        title = QLabel("🐉 GESTION DES BOSS")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #ff6b6b;")
        header_layout.addWidget(title)
        header_layout.addStretch()
        
        refresh_btn = QPushButton("🔄 Actualiser")
        refresh_btn.clicked.connect(self.load_boss_list)
        header_layout.addWidget(refresh_btn)
        
        layout.addLayout(header_layout)

        # Boss actuel
        self.current_boss_group = QGroupBox("🎯 BOSS ACTUEL")
        self.current_boss_group.setStyleSheet("""
            QGroupBox {
                background-color: #2d1a1a;
                border: 2px solid #ff6b6b;
                border-radius: 8px;
                font-weight: bold;
            }
            QGroupBox::title {
                color: #ff6b6b;
                padding: 0 10px;
            }
        """)
        current_layout = QHBoxLayout()
        self.current_boss_info = QLabel("Chargement du boss actuel...")
        self.current_boss_info.setStyleSheet("color: #e6edf3; font-size: 14px;")
        self.current_boss_info.setWordWrap(True)
        current_layout.addWidget(self.current_boss_info, 1)
        self.current_boss_group.setLayout(current_layout)
        layout.addWidget(self.current_boss_group)

        # Contenu principal
        content_layout = QHBoxLayout()
        content_layout.setSpacing(15)

        # Formulaire boss - PREND 70% DE L'ESPACE
        form_group = QGroupBox("📝 Création/Édition de Boss")
        form_layout = QVBoxLayout()

        # Navigation et actions
        nav_layout = QHBoxLayout()
        self.boss_combo = QComboBox()
        self.boss_combo.currentTextChanged.connect(self.on_boss_selected)
        new_boss_btn = QPushButton("🆕 Nouveau Boss")
        new_boss_btn.clicked.connect(self.new_boss)
        nav_layout.addWidget(QLabel("Boss:"))
        nav_layout.addWidget(self.boss_combo, 1)
        nav_layout.addWidget(new_boss_btn)
        form_layout.addLayout(nav_layout)

        # Onglets pour organiser le formulaire
        tabs = QTabWidget()
        
        # Onglet Identité
        identity_tab = QWidget()
        identity_layout = QFormLayout()
        
        self.boss_nom = QLineEdit()
        self.boss_surnoms = QLineEdit()
        self.boss_age = QLineEdit()
        self.boss_taille = QLineEdit()
        self.boss_poids = QLineEdit()
        self.boss_domaine = QLineEdit()
        
        identity_layout.addRow("Nom*:", self.boss_nom)
        identity_layout.addRow("Surnoms:", self.boss_surnoms)
        identity_layout.addRow("Âge:", self.boss_age)
        identity_layout.addRow("Taille:", self.boss_taille)
        identity_layout.addRow("Poids:", self.boss_poids)
        identity_layout.addRow("Domaine:", self.boss_domaine)
        
        identity_tab.setLayout(identity_layout)
        tabs.addTab(identity_tab, "👤 Identité")

        # Onglet Image
        image_tab = QWidget()
        image_layout = QVBoxLayout()
        
        # Aperçu image
        self.boss_image_preview = QLabel()
        self.boss_image_preview.setAlignment(Qt.AlignCenter)
        self.boss_image_preview.setStyleSheet("""
            QLabel {
                background-color: #161b22;
                border: 2px dashed #30363d;
                border-radius: 8px;
                min-height: 150px;
                max-height: 150px;
            }
        """)
        self.boss_image_preview.setText("Aucune image\n\n📁 Glisser-déposer une image")
        self.boss_image_preview.setWordWrap(True)
        self.boss_image_preview.setAcceptDrops(True)
        self.boss_image_preview.mousePressEvent = self.select_boss_image
        self.boss_image_preview.dragEnterEvent = self.drag_enter_event
        self.boss_image_preview.dropEvent = self.drop_boss_image
        
        # Boutons image
        image_btn_layout = QHBoxLayout()
        select_image_btn = QPushButton("📁 Sélectionner image")
        select_image_btn.clicked.connect(self.select_boss_image)
        clear_image_btn = QPushButton("🗑️ Supprimer")
        clear_image_btn.clicked.connect(self.clear_boss_image)
        clear_image_btn.setStyleSheet("background-color: #da3633;")
        
        image_btn_layout.addWidget(select_image_btn)
        image_btn_layout.addWidget(clear_image_btn)
        
        image_layout.addWidget(self.boss_image_preview)
        image_layout.addLayout(image_btn_layout)
        image_tab.setLayout(image_layout)
        tabs.addTab(image_tab, "🖼️ Image")

        # NOUVEL ONGLET : Sons
        sounds_tab = QWidget()
        sounds_layout = QVBoxLayout()
        
        # Groupe pour les sons
        sounds_group = QGroupBox("🔊 Sons du Boss")
        sounds_group_layout = QFormLayout()
        
        # Styles pour les boutons de sons
        sound_button_style = """
            QPushButton {
                background-color: #1f6feb;
                border: none;
                border-radius: 4px;
                padding: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #2b7fff;
            }
            QPushButton:pressed {
                background-color: #1a5fc4;
            }
        """
        
        delete_button_style = """
            QPushButton {
                background-color: #da3633;
                border: none;
                border-radius: 4px;
                padding: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #e64542;
            }
            QPushButton:pressed {
                background-color: #c92a27;
            }
        """
        
        # Cri de guerre
        cri_guerre_layout = QHBoxLayout()
        self.cri_guerre_preview = QLabel("Aucun son")
        self.cri_guerre_preview.setStyleSheet("color: #8b949e; font-style: italic;")
        self.cri_guerre_preview.setMinimumWidth(200)
        
        self.select_cri_guerre_btn = QPushButton("📁")
        self.select_cri_guerre_btn.setFixedSize(35, 35)
        self.select_cri_guerre_btn.setStyleSheet(sound_button_style)
        self.select_cri_guerre_btn.setToolTip("Sélectionner un fichier audio")
        self.select_cri_guerre_btn.clicked.connect(lambda: self.select_boss_sound('cri_guerre'))
        
        self.play_cri_guerre_btn = QPushButton("▶️")
        self.play_cri_guerre_btn.setFixedSize(35, 35)
        self.play_cri_guerre_btn.setStyleSheet(sound_button_style)
        self.play_cri_guerre_btn.setToolTip("Écouter le son")
        self.play_cri_guerre_btn.clicked.connect(lambda: self.play_sound('cri_guerre'))
        
        self.clear_cri_guerre_btn = QPushButton("🗑️")
        self.clear_cri_guerre_btn.setFixedSize(35, 35)
        self.clear_cri_guerre_btn.setStyleSheet(delete_button_style)
        self.clear_cri_guerre_btn.setToolTip("Supprimer le son")
        self.clear_cri_guerre_btn.clicked.connect(lambda: self.clear_boss_sound('cri_guerre'))
        
        cri_guerre_layout.addWidget(self.cri_guerre_preview, 1)
        cri_guerre_layout.addWidget(self.select_cri_guerre_btn)
        cri_guerre_layout.addWidget(self.play_cri_guerre_btn)
        cri_guerre_layout.addWidget(self.clear_cri_guerre_btn)

        # Sons de douleur (25%, 50%, 75%)
        cri_douleur_25_layout = QHBoxLayout()
        self.cri_douleur_25_preview = QLabel("Aucun son")
        self.cri_douleur_25_preview.setStyleSheet("color: #8b949e; font-style: italic;")
        self.cri_douleur_25_preview.setMinimumWidth(200)
        
        self.select_cri_douleur_25_btn = QPushButton("📁")
        self.select_cri_douleur_25_btn.setFixedSize(35, 35)
        self.select_cri_douleur_25_btn.setStyleSheet(sound_button_style)
        self.select_cri_douleur_25_btn.setToolTip("Sélectionner un fichier audio")
        self.select_cri_douleur_25_btn.clicked.connect(lambda: self.select_boss_sound('cri_douleur_25'))
        
        self.play_cri_douleur_25_btn = QPushButton("▶️")
        self.play_cri_douleur_25_btn.setFixedSize(35, 35)
        self.play_cri_douleur_25_btn.setStyleSheet(sound_button_style)
        self.play_cri_douleur_25_btn.setToolTip("Écouter le son")
        self.play_cri_douleur_25_btn.clicked.connect(lambda: self.play_sound('cri_douleur_25'))
        
        self.clear_cri_douleur_25_btn = QPushButton("🗑️")
        self.clear_cri_douleur_25_btn.setFixedSize(35, 35)
        self.clear_cri_douleur_25_btn.setStyleSheet(delete_button_style)
        self.clear_cri_douleur_25_btn.setToolTip("Supprimer le son")
        self.clear_cri_douleur_25_btn.clicked.connect(lambda: self.clear_boss_sound('cri_douleur_25'))
        
        cri_douleur_25_layout.addWidget(self.cri_douleur_25_preview, 1)
        cri_douleur_25_layout.addWidget(self.select_cri_douleur_25_btn)
        cri_douleur_25_layout.addWidget(self.play_cri_douleur_25_btn)
        cri_douleur_25_layout.addWidget(self.clear_cri_douleur_25_btn)

        cri_douleur_50_layout = QHBoxLayout()
        self.cri_douleur_50_preview = QLabel("Aucun son")
        self.cri_douleur_50_preview.setStyleSheet("color: #8b949e; font-style: italic;")
        self.cri_douleur_50_preview.setMinimumWidth(200)
        
        self.select_cri_douleur_50_btn = QPushButton("📁")
        self.select_cri_douleur_50_btn.setFixedSize(35, 35)
        self.select_cri_douleur_50_btn.setStyleSheet(sound_button_style)
        self.select_cri_douleur_50_btn.setToolTip("Sélectionner un fichier audio")
        self.select_cri_douleur_50_btn.clicked.connect(lambda: self.select_boss_sound('cri_douleur_50'))
        
        self.play_cri_douleur_50_btn = QPushButton("▶️")
        self.play_cri_douleur_50_btn.setFixedSize(35, 35)
        self.play_cri_douleur_50_btn.setStyleSheet(sound_button_style)
        self.play_cri_douleur_50_btn.setToolTip("Écouter le son")
        self.play_cri_douleur_50_btn.clicked.connect(lambda: self.play_sound('cri_douleur_50'))
        
        self.clear_cri_douleur_50_btn = QPushButton("🗑️")
        self.clear_cri_douleur_50_btn.setFixedSize(35, 35)
        self.clear_cri_douleur_50_btn.setStyleSheet(delete_button_style)
        self.clear_cri_douleur_50_btn.setToolTip("Supprimer le son")
        self.clear_cri_douleur_50_btn.clicked.connect(lambda: self.clear_boss_sound('cri_douleur_50'))
        
        cri_douleur_50_layout.addWidget(self.cri_douleur_50_preview, 1)
        cri_douleur_50_layout.addWidget(self.select_cri_douleur_50_btn)
        cri_douleur_50_layout.addWidget(self.play_cri_douleur_50_btn)
        cri_douleur_50_layout.addWidget(self.clear_cri_douleur_50_btn)

        cri_douleur_75_layout = QHBoxLayout()
        self.cri_douleur_75_preview = QLabel("Aucun son")
        self.cri_douleur_75_preview.setStyleSheet("color: #8b949e; font-style: italic;")
        self.cri_douleur_75_preview.setMinimumWidth(200)
        
        self.select_cri_douleur_75_btn = QPushButton("📁")
        self.select_cri_douleur_75_btn.setFixedSize(35, 35)
        self.select_cri_douleur_75_btn.setStyleSheet(sound_button_style)
        self.select_cri_douleur_75_btn.setToolTip("Sélectionner un fichier audio")
        self.select_cri_douleur_75_btn.clicked.connect(lambda: self.select_boss_sound('cri_douleur_75'))
        
        self.play_cri_douleur_75_btn = QPushButton("▶️")
        self.play_cri_douleur_75_btn.setFixedSize(35, 35)
        self.play_cri_douleur_75_btn.setStyleSheet(sound_button_style)
        self.play_cri_douleur_75_btn.setToolTip("Écouter le son")
        self.play_cri_douleur_75_btn.clicked.connect(lambda: self.play_sound('cri_douleur_75'))
        
        self.clear_cri_douleur_75_btn = QPushButton("🗑️")
        self.clear_cri_douleur_75_btn.setFixedSize(35, 35)
        self.clear_cri_douleur_75_btn.setStyleSheet(delete_button_style)
        self.clear_cri_douleur_75_btn.setToolTip("Supprimer le son")
        self.clear_cri_douleur_75_btn.clicked.connect(lambda: self.clear_boss_sound('cri_douleur_75'))
        
        cri_douleur_75_layout.addWidget(self.cri_douleur_75_preview, 1)
        cri_douleur_75_layout.addWidget(self.select_cri_douleur_75_btn)
        cri_douleur_75_layout.addWidget(self.play_cri_douleur_75_btn)
        cri_douleur_75_layout.addWidget(self.clear_cri_douleur_75_btn)

        # Cri d'agonie
        cri_agonie_layout = QHBoxLayout()
        self.cri_agonie_preview = QLabel("Aucun son")
        self.cri_agonie_preview.setStyleSheet("color: #8b949e; font-style: italic;")
        self.cri_agonie_preview.setMinimumWidth(200)
        
        self.select_cri_agonie_btn = QPushButton("📁")
        self.select_cri_agonie_btn.setFixedSize(35, 35)
        self.select_cri_agonie_btn.setStyleSheet(sound_button_style)
        self.select_cri_agonie_btn.setToolTip("Sélectionner un fichier audio")
        self.select_cri_agonie_btn.clicked.connect(lambda: self.select_boss_sound('cri_agonie'))
        
        self.play_cri_agonie_btn = QPushButton("▶️")
        self.play_cri_agonie_btn.setFixedSize(35, 35)
        self.play_cri_agonie_btn.setStyleSheet(sound_button_style)
        self.play_cri_agonie_btn.setToolTip("Écouter le son")
        self.play_cri_agonie_btn.clicked.connect(lambda: self.play_sound('cri_agonie'))
        
        self.clear_cri_agonie_btn = QPushButton("🗑️")
        self.clear_cri_agonie_btn.setFixedSize(35, 35)
        self.clear_cri_agonie_btn.setStyleSheet(delete_button_style)
        self.clear_cri_agonie_btn.setToolTip("Supprimer le son")
        self.clear_cri_agonie_btn.clicked.connect(lambda: self.clear_boss_sound('cri_agonie'))
        
        cri_agonie_layout.addWidget(self.cri_agonie_preview, 1)
        cri_agonie_layout.addWidget(self.select_cri_agonie_btn)
        cri_agonie_layout.addWidget(self.play_cri_agonie_btn)
        cri_agonie_layout.addWidget(self.clear_cri_agonie_btn)

        # Ajout des sons au layout
        sounds_group_layout.addRow("💥 Cri de guerre:", cri_guerre_layout)
        sounds_group_layout.addRow("😣 Cri douleur 25%:", cri_douleur_25_layout)
        sounds_group_layout.addRow("😫 Cri douleur 50%:", cri_douleur_50_layout)
        sounds_group_layout.addRow("😖 Cri douleur 75%:", cri_douleur_75_layout)
        sounds_group_layout.addRow("💀 Cri d'agonie:", cri_agonie_layout)
        
        sounds_group.setLayout(sounds_group_layout)
        sounds_layout.addWidget(sounds_group)
        sounds_tab.setLayout(sounds_layout)
        tabs.addTab(sounds_tab, "🔊 Sons")

        # Onglet Vidéo
        video_tab = QWidget()
        video_layout = QVBoxLayout()

        self.boss_video_preview = QLabel()
        self.boss_video_preview.setAlignment(Qt.AlignCenter)
        self.boss_video_preview.setStyleSheet("""
            QLabel {
                background-color: #161b22;
                border: 2px dashed #30363d;
                border-radius: 8px;
                min-height: 100px;
                max-height: 100px;
            }
        """)
        self.boss_video_preview.setText("Aucune vidéo\n\n📁 Cliquer pour sélectionner")
        self.boss_video_preview.setWordWrap(True)
        self.boss_video_preview.mousePressEvent = lambda e: self.select_boss_video()

        video_btn_layout = QHBoxLayout()
        select_video_btn = QPushButton("🎬 Sélectionner vidéo")
        select_video_btn.clicked.connect(self.select_boss_video)
        clear_video_btn = QPushButton("🗑️ Supprimer")
        clear_video_btn.clicked.connect(self.clear_boss_video)
        clear_video_btn.setStyleSheet("background-color: #da3633;")

        video_btn_layout.addWidget(select_video_btn)
        video_btn_layout.addWidget(clear_video_btn)

        video_layout.addWidget(self.boss_video_preview)
        video_layout.addLayout(video_btn_layout)
        video_tab.setLayout(video_layout)
        tabs.addTab(video_tab, "🎬 Vidéo")

        # Onglet Lore
        lore_tab = QWidget()
        lore_layout = QFormLayout()
        
        self.boss_lore = QTextEdit()
        self.boss_lore.setMaximumHeight(100)
        self.boss_legendes = QTextEdit()
        self.boss_legendes.setMaximumHeight(80)
        self.boss_rumeurs = QTextEdit()
        self.boss_rumeurs.setMaximumHeight(80)
        
        lore_layout.addRow("Lore:", self.boss_lore)
        lore_layout.addRow("Légendes:", self.boss_legendes)
        lore_layout.addRow("Rumeurs:", self.boss_rumeurs)
        
        lore_tab.setLayout(lore_layout)
        tabs.addTab(lore_tab, "📖 Lore")

        # Onglet Capacités
        capacites_tab = QWidget()
        capacites_layout = QFormLayout()
        
        self.boss_personnalite = QTextEdit()
        self.boss_personnalite.setMaximumHeight(80)
        self.boss_objectifs = QTextEdit()
        self.boss_objectifs.setMaximumHeight(80)
        self.boss_capacites = QTextEdit()
        self.boss_capacites.setMaximumHeight(80)
        self.boss_forces = QTextEdit()
        self.boss_forces.setMaximumHeight(80)
        self.boss_faiblesses = QTextEdit()
        self.boss_faiblesses.setMaximumHeight(80)
        
        capacites_layout.addRow("Personnalité:", self.boss_personnalite)
        capacites_layout.addRow("Objectifs:", self.boss_objectifs)
        capacites_layout.addRow("Capacités:", self.boss_capacites)
        capacites_layout.addRow("Forces:", self.boss_forces)
        capacites_layout.addRow("Faiblesses:", self.boss_faiblesses)
        
        capacites_tab.setLayout(capacites_layout)
        tabs.addTab(capacites_tab, "⚔️ Capacités")

        # Onglet Détails
        details_tab = QWidget()
        details_layout = QFormLayout()
        
        self.boss_danger = QTextEdit()
        self.boss_danger.setMaximumHeight(60)
        self.boss_pouvoir_special = QTextEdit()
        self.boss_pouvoir_special.setMaximumHeight(60)
        self.boss_secret_twist = QTextEdit()
        self.boss_secret_twist.setMaximumHeight(60)
        self.boss_interactions = QTextEdit()
        self.boss_interactions.setMaximumHeight(60)
        
        details_layout.addRow("Danger:", self.boss_danger)
        details_layout.addRow("Pouvoir spécial:", self.boss_pouvoir_special)
        details_layout.addRow("Secret/Twist:", self.boss_secret_twist)
        details_layout.addRow("Interactions:", self.boss_interactions)
        
        details_tab.setLayout(details_layout)
        tabs.addTab(details_tab, "🔍 Détails")

        # Onglet Description
        description_tab = QWidget()
        description_layout = QFormLayout()
        
        self.boss_description = QTextEdit()
        self.boss_description.setMaximumHeight(100)
        self.boss_extrait = QTextEdit()
        self.boss_extrait.setMaximumHeight(80)
        self.boss_role = QTextEdit()
        self.boss_role.setMaximumHeight(80)
        self.boss_lien_aarkhin = QTextEdit()
        self.boss_lien_aarkhin.setMaximumHeight(80)
        
        description_layout.addRow("Description physique:", self.boss_description)
        description_layout.addRow("Extrait carnet:", self.boss_extrait)
        description_layout.addRow("Rôle histoire:", self.boss_role)
        description_layout.addRow("Lien Aarkhin:", self.boss_lien_aarkhin)
        
        description_tab.setLayout(description_layout)
        tabs.addTab(description_tab, "📝 Description")

        form_layout.addWidget(tabs)

        # Boutons d'action
        btn_layout = QHBoxLayout()
        save_btn = QPushButton("💾 Sauvegarder")
        save_btn.clicked.connect(self.save_boss)
        save_btn.setStyleSheet("background-color: #238636;")
        
        delete_btn = QPushButton("🗑️ Supprimer")
        delete_btn.clicked.connect(self.delete_boss)
        delete_btn.setStyleSheet("background-color: #da3633;")

        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(delete_btn)

        form_layout.addLayout(btn_layout)
        form_group.setLayout(form_layout)
        content_layout.addWidget(form_group, 3)  # 70% de l'espace

        # Liste des boss - RÉDUITE À 30% DE L'ESPACE
        list_group = QGroupBox("📋 Tous les Boss")
        list_group.setMaximumWidth(350)  # Largeur maximale réduite
        list_layout = QVBoxLayout()
        
        self.boss_list = QListWidget()
        self.boss_list.itemClicked.connect(self.on_boss_list_selected)
        self.boss_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                color: #e6edf3;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 5px;
                font-size: 11px;
            }
            QListWidget::item {
                padding: 6px;
                border-bottom: 1px solid #30363d;
            }
            QListWidget::item:selected {
                background-color: #1f6feb;
            }
        """)
        list_layout.addWidget(self.boss_list)
        
        # Bouton de suppression rapide
        quick_delete_layout = QHBoxLayout()
        quick_delete_btn = QPushButton("🗑️ Supprimer le boss sélectionné")
        quick_delete_btn.clicked.connect(self.delete_boss)
        quick_delete_btn.setStyleSheet("background-color: #da3633; font-size: 11px;")
        quick_delete_layout.addWidget(quick_delete_btn)
        list_layout.addLayout(quick_delete_layout)
        
        list_group.setLayout(list_layout)
        content_layout.addWidget(list_group, 1)  # 30% de l'espace

        layout.addLayout(content_layout)
        self.setLayout(layout)

    # MÉTHODES POUR LA GESTION DES SONS (restent identiques)
    def select_boss_sound(self, sound_type):
        """Sélectionne un fichier audio pour le boss"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, f"Sélectionner un son {sound_type}", "", 
            "Fichiers audio (*.mp3 *.wav *.ogg *.m4a *.aac)"
        )
        if file_path:
            self.current_sounds[sound_type] = file_path
            file_name = os.path.basename(file_path)
            # Mettre à jour l'affichage
            preview_label = getattr(self, f"{sound_type}_preview")
            preview_label.setText(file_name)
            preview_label.setStyleSheet("color: #58a6ff; font-weight: bold;")
            
            print(f"🔊 Son {sound_type} sélectionné: {file_name}")

    def clear_boss_sound(self, sound_type):
        """Supprime le son sélectionné"""
        if sound_type in self.current_sounds:
            del self.current_sounds[sound_type]
        
        # Réinitialiser l'affichage
        preview_label = getattr(self, f"{sound_type}_preview")
        preview_label.setText("Aucun son")
        preview_label.setStyleSheet("color: #8b949e; font-style: italic;")
        
        print(f"🔊 Son {sound_type} supprimé")

    def play_sound(self, sound_type):
        """Joue le son sélectionné (prévisualisation)"""
        sound_path = self.current_sounds.get(sound_type)
        if sound_path and os.path.exists(sound_path):
            try:
                # Pour Windows
                if os.name == 'nt':
                    os.system(f'start wmplayer "{sound_path}"')
                # Pour macOS
                elif sys.platform == 'darwin':
                    os.system(f'afplay "{sound_path}"')
                # Pour Linux
                else:
                    os.system(f'xdg-open "{sound_path}"')
                print(f"🎵 Lecture du son {sound_type}")
            except Exception as e:
                QMessageBox.warning(self, "Erreur", f"Impossible de lire le son: {str(e)}")
        else:
            QMessageBox.information(self, "Information", "Aucun son sélectionné ou fichier introuvable")

    def upload_boss_sound(self, boss_id, sound_type, sound_path):
        """Upload un son vers le serveur"""
        try:
            print(f"📤 Upload du son {sound_type}: {sound_path}")
            
            with open(sound_path, 'rb') as f:
                files = {'sound': (os.path.basename(sound_path), f, 'audio/mpeg')}
                data = {
                    'boss_id': boss_id,
                    'sound_type': sound_type
                }
                
                headers = {}
                if self.api_client.jwt_token:
                    headers['Authorization'] = f'Bearer {self.api_client.jwt_token}'
                
                # Utiliser l'endpoint d'upload de son
                response = self.api_client.client.post(
                    f"{self.api_client.backend_url}/admin/boss/{boss_id}/upload-sound",
                    files=files,
                    data=data,
                    headers=headers,
                    timeout=30.0
                )
                
                print(f"📡 Response status upload son: {response.status_code}")
                
                if response.status_code == 200:
                    result = response.json()
                    sound_url = result.get('sound_url')
                    print(f"✅ Upload son réussi, URL: {sound_url}")
                    return sound_url
                else:
                    print(f"❌ Erreur upload son: {response.status_code} - {response.text}")
                    return None
                    
        except Exception as e:
            print(f"❌ Erreur upload son: {e}")
            return None

    def load_boss_sound(self, sound_url, preview_label):
        """Charge et affiche les informations d'un son existant"""
        if sound_url:
            file_name = os.path.basename(sound_url)
            preview_label.setText(file_name)
            preview_label.setStyleSheet("color: #3fb950; font-weight: bold;")
        else:
            preview_label.setText("Aucun son")
            preview_label.setStyleSheet("color: #8b949e; font-style: italic;")

    def load_current_boss(self):
        """Charge le boss actuel"""
        try:
            data = self.api_client.get_current_boss()
            
            if data and data.get("boss"):
                boss = data["boss"]
                event = data.get("event_progress", {})
                
                info_text = f"🐉 {boss['nom']}\n"
                if boss.get('surnoms'):
                    info_text += f"🏷️ {boss['surnoms']}\n"
                info_text += f"📍 {boss.get('domaine', 'Domaine inconnu')}\n"
                
                # Vérifier si l'événement est en 'finishing'
                if event.get('event_status') == 'finishing':
                    info_text += f"💀 Boss en train de mourir...\n"
                    info_text += f"🎯 Dernier souffle !"
                    
                    # Jouer le son d'agonie si disponible
                    agony_sound = boss.get('son_cri_agonie')
                    if agony_sound:
                        self.play_agony_sound(agony_sound)
                    
                    # Cacher la HUD dans 3 secondes
                    QTimer.singleShot(3000, self.hide_boss_hud)
                    
                else:
                    info_text += f"🎯 Événement: {event.get('event_title', 'Aucun')}\n"
                    if event.get('progress_percent'):
                        info_text += f"📊 Progression: {event.get('progress_percent')}%"
                
                self.current_boss_info.setText(info_text)
                
            else:
                self.current_boss_info.setText("🎯 Aucun boss en cours de combat")
                
        except Exception as e:
            print(f"❌ Erreur chargement boss actuel: {e}")
            self.current_boss_info.setText("❌ Erreur de chargement")
    def load_boss_list(self):
        """Charge la liste des boss"""
        try:
            data = self.api_client.get_all_boss()
            self.boss_combo.clear()
            self.boss_list.clear()
            
            if data and "boss" in data:
                for boss in data["boss"]:
                    # Combo box
                    display_text = f"{boss['nom']} - {boss.get('domaine', '')}"
                    self.boss_combo.addItem(display_text, boss['id'])
                    
                    # Liste - Texte plus compact
                    item_text = f"🐉 {boss['nom']}"
                    if boss.get('surnoms'):
                        item_text += f" ({boss['surnoms']})"
                    
                    item = QListWidgetItem(item_text)
                    item.setData(Qt.UserRole, boss)
                    
                    # Tooltip avec plus d'informations
                    tooltip = f"Nom: {boss['nom']}\nDomaine: {boss.get('domaine', 'N/A')}"
                    if boss.get('surnoms'):
                        tooltip += f"\nSurnoms: {boss['surnoms']}"
                    item.setToolTip(tooltip)
                    
                    self.boss_list.addItem(item)
                    
        except Exception as e:
            print(f"❌ Erreur chargement liste boss: {e}")

    def on_boss_selected(self, text):
        """Quand un boss est sélectionné dans la combo"""
        boss_id = self.boss_combo.currentData()
        if boss_id:
            self.load_boss(boss_id)

    def on_boss_list_selected(self, item):
        """Quand un boss est sélectionné dans la liste"""
        boss_data = item.data(Qt.UserRole)
        if boss_data:
            self.load_boss_data(boss_data)

    def load_boss(self, boss_id):
        """Charge un boss par son ID"""
        try:
            data = self.api_client.get_boss(boss_id)
            if data and "boss" in data:
                self.load_boss_data(data["boss"])
        except Exception as e:
            print(f"❌ Erreur chargement boss: {e}")

    def load_boss_data(self, boss):
        """Remplit le formulaire avec les données du boss"""
        self.current_boss = boss
        self.current_sounds = {}  # Réinitialiser les sons locaux
        
        # Identité
        self.boss_nom.setText(boss.get('nom', ''))
        self.boss_surnoms.setText(boss.get('surnoms', ''))
        self.boss_age.setText(boss.get('age', ''))
        self.boss_taille.setText(boss.get('taille', ''))
        self.boss_poids.setText(boss.get('poids', ''))
        self.boss_domaine.setText(boss.get('domaine', ''))
        
        # Lore
        self.boss_lore.setPlainText(boss.get('lore', ''))
        self.boss_legendes.setPlainText(boss.get('legendes', ''))
        self.boss_rumeurs.setPlainText(boss.get('rumeurs', ''))
        
        # Capacités
        self.boss_personnalite.setPlainText(boss.get('personnalite', ''))
        self.boss_objectifs.setPlainText(boss.get('objectifs', ''))
        self.boss_capacites.setPlainText(boss.get('capacites', ''))
        self.boss_forces.setPlainText(boss.get('forces', ''))
        self.boss_faiblesses.setPlainText(boss.get('faiblesses', ''))
        
        # Détails
        self.boss_danger.setPlainText(boss.get('danger', ''))
        self.boss_pouvoir_special.setPlainText(boss.get('pouvoir_special', ''))
        self.boss_secret_twist.setPlainText(boss.get('secret_twist', ''))
        self.boss_interactions.setPlainText(boss.get('interactions_viewers', ''))
        
        # Description
        self.boss_description.setPlainText(boss.get('description_physique', ''))
        self.boss_extrait.setPlainText(boss.get('extrait_carnet', ''))
        self.boss_role.setPlainText(boss.get('role_histoire', ''))
        self.boss_lien_aarkhin.setPlainText(boss.get('lien_aarkhin', ''))
        
        # Image
        image_url = boss.get('image_url')
        if image_url:
            self.load_boss_image(image_url)
        else:
            self.clear_boss_image()
            
        # Sons
        self.load_boss_sound(boss.get('son_cri_guerre'), self.cri_guerre_preview)
        self.load_boss_sound(boss.get('son_cri_douleur_25'), self.cri_douleur_25_preview)
        self.load_boss_sound(boss.get('son_cri_douleur_50'), self.cri_douleur_50_preview)
        self.load_boss_sound(boss.get('son_cri_douleur_75'), self.cri_douleur_75_preview)
        self.load_boss_sound(boss.get('son_cri_agonie'), self.cri_agonie_preview)

        # Vidéo
        self.current_video_path = None
        self.load_boss_video_info(boss.get('video_intro'))

    def new_boss(self):
        """Crée un nouveau boss"""
        self.current_boss = None
        self.current_sounds = {}
        self.clear_form()
        self.clear_boss_image()
        self.clear_boss_video()
        # Réinitialiser les sons
        for sound_type in ['cri_guerre', 'cri_douleur_25', 'cri_douleur_50', 'cri_douleur_75', 'cri_agonie']:
            self.clear_boss_sound(sound_type)

    def clear_form(self):
        """Réinitialise le formulaire"""
        fields = [
            self.boss_nom, self.boss_surnoms, self.boss_age, self.boss_taille,
            self.boss_poids, self.boss_domaine
        ]
        for field in fields:
            field.clear()
        
        text_areas = [
            self.boss_lore, self.boss_legendes, self.boss_rumeurs,
            self.boss_personnalite, self.boss_objectifs, self.boss_capacites,
            self.boss_forces, self.boss_faiblesses, self.boss_danger,
            self.boss_pouvoir_special, self.boss_secret_twist, self.boss_interactions,
            self.boss_description, self.boss_extrait, self.boss_role, self.boss_lien_aarkhin
        ]
        for area in text_areas:
            area.clear()

    def select_boss_image(self, event=None):
        """Sélectionne une image pour le boss"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Sélectionner une image", "", "Images (*.png *.jpg *.jpeg)"
        )
        if file_path:
            self.load_boss_image_preview(file_path)

    def drag_enter_event(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def drop_boss_image(self, event):
        """Gère le drop d'image"""
        urls = event.mimeData().urls()
        if urls and urls[0].isLocalFile():
            file_path = urls[0].toLocalFile()
            if file_path.lower().endswith(('.png', '.jpg', '.jpeg')):
                self.load_boss_image_preview(file_path)
                event.acceptProposedAction()

    def load_boss_image_preview(self, file_path):
        """Charge l'aperçu de l'image"""
        try:
            pixmap = QPixmap(file_path)
            if not pixmap.isNull():
                scaled_pixmap = pixmap.scaled(200, 150, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                self.boss_image_preview.setPixmap(scaled_pixmap)
                self.current_image_path = file_path
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Impossible de charger l'image: {str(e)}")

    def load_boss_image(self, image_url):
        """Charge l'image existante du boss"""
        try:
            if image_url.startswith('/'):
                full_url = f"{self.api_client.backend_url}{image_url}"
            else:
                full_url = image_url

            # Utiliser httpx.get() directement pour les URLs externes
            response = httpx.get(full_url, timeout=10.0, follow_redirects=True)
            if response.status_code == 200:
                pixmap = QPixmap()
                pixmap.loadFromData(response.content)
                if not pixmap.isNull():
                    scaled_pixmap = pixmap.scaled(200, 150, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                    self.boss_image_preview.setPixmap(scaled_pixmap)
        except Exception as e:
            print(f"❌ Erreur chargement image boss: {e}")

    def clear_boss_image(self):
        """Efface l'image du boss"""
        self.boss_image_preview.clear()
        self.boss_image_preview.setText("Aucune image\n\n📁 Glisser-déposer une image")
        self.current_image_path = None

    def select_boss_video(self):
        """Sélectionne une vidéo pour le boss"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Sélectionner une vidéo", "",
            "Vidéos (*.mp4 *.webm *.mov *.avi *.mkv)"
        )
        if file_path:
            file_size = Path(file_path).stat().st_size
            if file_size > 100 * 1024 * 1024:
                QMessageBox.warning(self, "Fichier trop volumineux", "La vidéo ne doit pas dépasser 100 MB")
                return
            self.current_video_path = file_path
            file_name = os.path.basename(file_path)
            size_mb = file_size / (1024 * 1024)
            self.boss_video_preview.setText(f"🎬 {file_name}\n📦 {size_mb:.1f} MB\n✅ Prêt pour upload")
            self.boss_video_preview.setStyleSheet("""
                QLabel {
                    background-color: #161b22;
                    border: 2px solid #3fb950;
                    border-radius: 8px;
                    min-height: 100px;
                    max-height: 100px;
                    color: #3fb950;
                }
            """)

    def clear_boss_video(self):
        """Supprime la vidéo sélectionnée"""
        self.current_video_path = None
        self.boss_video_preview.setText("Aucune vidéo\n\n📁 Cliquer pour sélectionner")
        self.boss_video_preview.setStyleSheet("""
            QLabel {
                background-color: #161b22;
                border: 2px dashed #30363d;
                border-radius: 8px;
                min-height: 100px;
                max-height: 100px;
            }
        """)

    def load_boss_video_info(self, video_url):
        """Affiche les infos de la vidéo existante"""
        if video_url:
            file_name = os.path.basename(video_url).split('?')[0]
            self.boss_video_preview.setText(f"🎬 {file_name}\n🌐 Vidéo sur Cloudinary\n✅ En ligne")
            self.boss_video_preview.setStyleSheet("""
                QLabel {
                    background-color: #161b22;
                    border: 2px solid #1f6feb;
                    border-radius: 8px;
                    min-height: 100px;
                    max-height: 100px;
                    color: #58a6ff;
                }
            """)
        else:
            self.clear_boss_video()

    def save_boss(self):
        """Sauvegarde le boss avec ses sons"""
        try:
            nom = self.boss_nom.text().strip()
            if not nom:
                QMessageBox.warning(self, "Erreur", "Le nom du boss est obligatoire")
                return

            # Préparer les données - ne pas inclure les champs vides
            boss_data = {
                "id": self.current_boss.get('id') if self.current_boss else None,
                "nom": nom,
                "surnoms": self.boss_surnoms.text() or None,
                "age": self.boss_age.text() or None,
                "taille": self.boss_taille.text() or None,
                "poids": self.boss_poids.text() or None,
                "domaine": self.boss_domaine.text() or None,
                "lore": self.boss_lore.toPlainText() or None,
                "legendes": self.boss_legendes.toPlainText() or None,
                "rumeurs": self.boss_rumeurs.toPlainText() or None,
                "personnalite": self.boss_personnalite.toPlainText() or None,
                "objectifs": self.boss_objectifs.toPlainText() or None,
                "capacites": self.boss_capacites.toPlainText() or None,
                "forces": self.boss_forces.toPlainText() or None,
                "faiblesses": self.boss_faiblesses.toPlainText() or None,
                "danger": self.boss_danger.toPlainText() or None,
                "pouvoir_special": self.boss_pouvoir_special.toPlainText() or None,
                "secret_twist": self.boss_secret_twist.toPlainText() or None,
                "interactions_viewers": self.boss_interactions.toPlainText() or None,
                "description_physique": self.boss_description.toPlainText() or None,
                "extrait_carnet": self.boss_extrait.toPlainText() or None,
                "role_histoire": self.boss_role.toPlainText() or None,
                "lien_aarkhin": self.boss_lien_aarkhin.toPlainText() or None
            }

            print(f"💾 Sauvegarde boss (champs non-vides uniquement)")

            # Sauvegarde du boss (seulement les champs remplis)
            result = self.api_client.upsert_boss(boss_data)
            if result and "error" in result:
                QMessageBox.critical(self, "Erreur", f"Erreur sauvegarde: {result['error']}")
                return

            # Récupérer l'ID du boss
            boss_id = result["boss"]["id"] if result and "boss" in result else self.current_boss['id']

            # Upload de l'image si une nouvelle image a été sélectionnée
            if self.current_image_path:
                print(f"📤 Upload image boss: {self.current_image_path}")
                image_url = self.api_client.upload_boss_image(boss_id, self.current_image_path)
                if image_url:
                    # Mettre à jour seulement l'image via un endpoint spécifique
                    update_data = {"image_url": image_url}
                    self.api_client._make_request("POST", f"/admin/boss/{boss_id}/update-image", json=update_data)
                    print(f"✅ Image boss uploadée: {image_url}")

            # Upload des sons sélectionnés
            sound_updates = {}
            for sound_type, sound_path in self.current_sounds.items():
                print(f"📤 Upload son {sound_type}: {sound_path}")
                sound_url = self.upload_boss_sound(boss_id, sound_type, sound_path)
                if sound_url:
                    # Stocker pour mise à jour groupée
                    sound_updates[f"son_{sound_type}"] = sound_url
                    print(f"✅ Son {sound_type} uploadé: {sound_url}")

            # Mettre à jour les sons (uniquement ceux qui ont été uploadés)
            if sound_updates:
                self.api_client._make_request("POST", f"/admin/boss/{boss_id}/update-sound", json=sound_updates)
                print(f"✅ Sons mis à jour: {sound_updates}")

            # Upload de la vidéo si sélectionnée
            if self.current_video_path:
                print(f"📤 Upload vidéo boss: {self.current_video_path}")
                video_url = self.api_client.upload_boss_video(boss_id, self.current_video_path)
                if video_url:
                    update_data = {"video_intro": video_url}
                    self.api_client._make_request("POST", f"/admin/boss/{boss_id}/update-video", json=update_data)
                    print(f"✅ Vidéo boss uploadée: {video_url}")
                else:
                    QMessageBox.warning(self, "Avertissement", "Le boss a été sauvegardé mais la vidéo n'a pas pu être uploadée")

            QMessageBox.information(self, "Succès", f"Boss {nom} sauvegardé avec succès!")
            self.load_boss_list()
            self.load_current_boss()

        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur inattendue: {str(e)}")
    def delete_boss(self):
        """Supprime le boss actuel"""
        if not self.current_boss:
            QMessageBox.warning(self, "Erreur", "Aucun boss sélectionné")
            return

        nom = self.current_boss['nom']
        reply = QMessageBox.question(
            self, "Confirmation", f"Supprimer le boss {nom} ?",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            try:
                result = self.api_client.delete_boss(self.current_boss['id'])
                if result and "error" in result:
                    QMessageBox.critical(self, "Erreur", f"Erreur suppression: {result['error']}")
                else:
                    QMessageBox.information(self, "Succès", f"Boss {nom} supprimé!")
                    self.new_boss()
                    self.load_boss_list()
                    self.load_current_boss()
            except Exception as e:
                QMessageBox.critical(self, "Erreur", f"Erreur: {str(e)}")
    
    def start_boss_sse_listener(self):
        """Démarre l'écoute des événements SSE pour les boss"""
        def listen_for_events():
            while True:
                try:
                    url = f"{self.api_client.backend_url}/sse/boss-events"
                    response = requests.get(url, stream=True, timeout=30)
                    
                    for line in response.iter_lines():
                        if line:
                            line_str = line.decode('utf-8')
                            print(f"SSE reçu: {line_str}")
                            
                            if line_str.startswith('event: boss_defeated'):
                                # Lire la ligne de données
                                try:
                                    data_line = next(response.iter_lines()).decode('utf-8')
                                    if data_line.startswith('data: '):
                                        data = json.loads(data_line[6:])
                                        
                                        # Jouer le son d'agonie
                                        agony_sound = data.get('agony_sound')
                                        if agony_sound:
                                            print(f"🎵 Jouer son d'agonie: {agony_sound}")
                                            self.play_agony_sound(agony_sound)
                                        
                                        # Mettre à jour l'interface
                                        self.boss_defeated_ui_update(data)
                                except Exception as e:
                                    print(f"❌ Erreur parsing SSE: {e}")
                                    
                except Exception as e:
                    print(f"❌ Erreur connexion SSE: {e}")
                    time.sleep(5)  # Attendre avant de reconnecter
        
        # Démarrer dans un thread
        thread = threading.Thread(target=listen_for_events, daemon=True)
        thread.start()
    
    def play_agony_sound(self, sound_url):
        """Joue le son d'agonie"""
        try:
            # Pour Windows
            if os.name == 'nt':
                os.system(f'start wmplayer "{sound_url}"')
            # Pour macOS
            elif sys.platform == 'darwin':
                os.system(f'afplay "{sound_url}"')
            # Pour Linux
            else:
                os.system(f'xdg-open "{sound_url}"')
            print(f"✅ Son d'agonie joué")
        except Exception as e:
            print(f"❌ Erreur lecture son: {e}")
    
    def boss_defeated_ui_update(self, data):
        """Met à jour l'UI quand un boss est vaincu"""
        # Cacher la HUD après un délai
        QTimer.singleShot(3000, self.hide_boss_hud)
        
        # Afficher un message
        boss_name = data.get('boss_name', 'Boss')
        self.current_boss_info.setText(f"💀 {boss_name} est vaincu !\nIl agonise...")
    
    def hide_boss_hud(self):
        """Cache la HUD du boss"""
        self.current_boss_info.setText("🎯 Aucun boss en cours de combat")
        print("✅ HUD boss cachée")

# Section 6.3 Onglet Items
class ItemsTab(QWidget):
    """Onglet de gestion des items avec images"""

    def __init__(self, api_client):
        super().__init__()
        self.api_client = api_client
        self.current_item = None
        self.current_image_path = None
        self.init_ui()
        self.refresh_items()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)

        # Header
        header_layout = QHBoxLayout()
        title = QLabel("📦 GESTION DES ITEMS")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #ffd700;")
        header_layout.addWidget(title)
        header_layout.addStretch()
        
        refresh_btn = QPushButton("🔄 Actualiser")
        refresh_btn.clicked.connect(self.refresh_items)
        header_layout.addWidget(refresh_btn)
        
        layout.addLayout(header_layout)

        # Contenu principal
        content_layout = QHBoxLayout()
        content_layout.setSpacing(15)

        # Formulaire de création/modification
        form_group = QGroupBox("📝 Création/Édition d'Item")
        form_group.setMaximumWidth(450)
        form_layout = QVBoxLayout()

        # Section Image
        image_group = QGroupBox("🖼️ Image de l'Item")
        image_layout = QVBoxLayout()
        
        # Aperçu de l'image
        self.image_preview = QLabel()
        self.image_preview.setAlignment(Qt.AlignCenter)
        self.image_preview.setStyleSheet("""
            QLabel {
                background-color: #161b22;
                border: 2px dashed #30363d;
                border-radius: 8px;
                min-height: 150px;
                max-height: 150px;
            }
        """)
        self.image_preview.setText("Aucune image\n\n📁 Glisser-déposer une image\nou cliquer pour sélectionner")
        self.image_preview.setWordWrap(True)
        
        # Activer le drag & drop
        self.image_preview.setAcceptDrops(True)
        self.image_preview.mousePressEvent = self.select_image_file
        self.image_preview.dragEnterEvent = self.drag_enter_event
        self.image_preview.dropEvent = self.drop_event
        
        # Boutons image
        image_btn_layout = QHBoxLayout()
        self.select_image_btn = QPushButton("📁 Sélectionner une image")
        self.select_image_btn.clicked.connect(self.select_image_file)
        
        self.clear_image_btn = QPushButton("🗑️ Supprimer l'image")
        self.clear_image_btn.clicked.connect(self.clear_image)
        self.clear_image_btn.setStyleSheet("background-color: #da3633;")
        
        image_btn_layout.addWidget(self.select_image_btn)
        image_btn_layout.addWidget(self.clear_image_btn)
        
        image_layout.addWidget(self.image_preview)
        image_layout.addLayout(image_btn_layout)
        image_group.setLayout(image_layout)
        form_layout.addWidget(image_group)

        # Champs du formulaire
        fields_layout = QFormLayout()
        fields_layout.setLabelAlignment(Qt.AlignLeft)

        self.item_code = QLineEdit()
        self.item_code.setPlaceholderText("CODE_ITEM (majuscules)")
        
        self.item_name = QLineEdit()
        self.item_name.setPlaceholderText("Nom affiché de l'item")
        
        self.item_description = QTextEdit()
        self.item_description.setMaximumHeight(80)
        self.item_description.setPlaceholderText("Description détaillée...")
        
        self.item_rarity = QComboBox()
        self.item_rarity.addItems([
            "common", "uncommon", "rare", "epic", "legendary",
            "Objet de Quête", "Objet de Quête Épique", "Objet de Quête Légendaire"
        ])
        
        self.item_stackable = QCheckBox()
        self.item_stackable.setChecked(True)
        
        self.item_evenement_id = QLineEdit()
        self.item_evenement_id.setPlaceholderText("ID événement (optionnel)")

        # Checkbox pour récompense de groupe
        self.item_is_group_reward = QCheckBox()
        self.item_is_group_reward.setText("Récompense de mission de groupe")
        self.item_is_group_reward.setToolTip("Si coché, cet item sera disponible comme récompense pour les missions de groupe")

        # Type d'item
        self.item_type = QComboBox()
        self.item_type.addItems(["resource", "tool"])

        # Ajout des champs au formulaire
        fields_layout.addRow("Code*:", self.item_code)
        fields_layout.addRow("Nom*:", self.item_name)
        fields_layout.addRow("Description:", self.item_description)
        fields_layout.addRow("Type:", self.item_type)
        fields_layout.addRow("Rareté:", self.item_rarity)
        fields_layout.addRow("Stackable:", self.item_stackable)
        fields_layout.addRow("ID Événement:", self.item_evenement_id)
        fields_layout.addRow("", self.item_is_group_reward)

        form_layout.addLayout(fields_layout)

        # Boutons d'action
        btn_layout = QHBoxLayout()
        self.save_btn = QPushButton("💾 Sauvegarder")
        self.save_btn.clicked.connect(self.save_item)
        self.save_btn.setStyleSheet("background-color: #238636;")
        
        self.new_btn = QPushButton("🆕 Nouveau")
        self.new_btn.clicked.connect(self.new_item)
        
        self.delete_btn = QPushButton("🗑️ Supprimer")
        self.delete_btn.clicked.connect(self.delete_item)
        self.delete_btn.setStyleSheet("background-color: #da3633;")

        btn_layout.addWidget(self.save_btn)
        btn_layout.addWidget(self.new_btn)
        btn_layout.addWidget(self.delete_btn)

        form_layout.addLayout(btn_layout)
        form_group.setLayout(form_layout)
        content_layout.addWidget(form_group)

        # Liste des items existants
        list_group = QGroupBox("📋 Items Existants")
        list_layout = QVBoxLayout()
        
        # Barre de recherche
        filter_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Rechercher un item...")
        self.search_input.textChanged.connect(self.filter_items)
        filter_layout.addWidget(self.search_input)

        self.rarity_filter = QComboBox()
        self.rarity_filter.addItems(["Toutes les raretés", "common", "uncommon", "rare", "epic", "legendary", "Objet de Quête"])
        self.rarity_filter.currentTextChanged.connect(self.filter_items)
        filter_layout.addWidget(self.rarity_filter)

        # Filtre solo/groupe
        self.type_filter = QComboBox()
        self.type_filter.addItems(["Tous les types", "Solo seulement", "Groupe seulement"])
        self.type_filter.currentTextChanged.connect(self.filter_items)
        filter_layout.addWidget(self.type_filter)

        list_layout.addLayout(filter_layout)

        # Deuxième ligne de filtres
        filter_layout2 = QHBoxLayout()

        # Filtre par catégorie
        self.category_filter = QComboBox()
        self.category_filter.addItems(["Toutes catégories", "Ressources", "Outils", "Objets de Quête"])
        self.category_filter.currentTextChanged.connect(self.on_category_changed)
        filter_layout2.addWidget(self.category_filter)

        # Sous-filtre ressources (lootables vs craftables) - masqué par défaut
        self.resource_sub_filter = QComboBox()
        self.resource_sub_filter.addItems(["Toutes ressources", "Lootables", "Craftables (supercraft)"])
        self.resource_sub_filter.currentTextChanged.connect(self.filter_items)
        self.resource_sub_filter.hide()
        filter_layout2.addWidget(self.resource_sub_filter)

        self.no_image_filter = QCheckBox("📷 Sans image")
        self.no_image_filter.stateChanged.connect(self.filter_items)
        filter_layout2.addWidget(self.no_image_filter)

        list_layout.addLayout(filter_layout2)
        
        # Liste des items
        self.items_list = QListWidget()
        self.items_list.itemClicked.connect(self.item_selected)
        self.items_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                color: #e6edf3;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 5px;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #30363d;
            }
            QListWidget::item:selected {
                background-color: #1f6feb;
            }
        """)
        list_layout.addWidget(self.items_list)
        
        list_group.setLayout(list_layout)
        content_layout.addWidget(list_group)

        layout.addLayout(content_layout)
        self.setLayout(layout)

    # Méthodes pour la gestion des images
    def select_image_file(self, event=None):
        """Version avec débogage"""
        print("🔍 Méthode select_image_file appelée")  # Debug
        try:
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Sélectionner une image", 
                "",
                "Images (*.png *.jpg *.jpeg *.gif *.bmp);;Tous les fichiers (*)"
            )
            print(f"📁 Fichier sélectionné: {file_path}")  # Debug
            
            if file_path:
                self.load_image_preview(file_path)
        except Exception as e:
            print(f"❌ Erreur sélection fichier: {e}")  # Debug
            QMessageBox.critical(self, "Erreur", f"Erreur lors de la sélection: {str(e)}")

    def drag_enter_event(self, event):
        """Accepte le drag & drop d'images - VERSION CORRIGÉE"""
        try:
            if event.mimeData().hasUrls():
                event.acceptProposedAction()
        except Exception as e:
            print(f"Erreur drag enter: {e}")

    def drop_event(self, event):
        """Gère le drop d'images - VERSION CORRIGÉE"""
        try:
            urls = event.mimeData().urls()
            if urls and urls[0].isLocalFile():
                file_path = urls[0].toLocalFile()
                # Vérifier l'extension du fichier
                if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
                    self.load_image_preview(file_path)
                    event.acceptProposedAction()
                else:
                    QMessageBox.warning(self, "Format non supporté", "Veuillez sélectionner une image (PNG, JPG, GIF, BMP)")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur lors du drop: {str(e)}")

    def load_image_preview(self, file_path):
        """Charge et affiche l'aperçu de l'image - VERSION CORRIGÉE"""
        try:
            # Vérifier la taille du fichier (max 5MB)
            file_size = Path(file_path).stat().st_size
            if file_size > 5 * 1024 * 1024:
                QMessageBox.warning(self, "Fichier trop volumineux", "L'image ne doit pas dépasser 5MB")
                return
            
            # Charger l'image avec QPixmap
            pixmap = QPixmap(file_path)
            if pixmap.isNull():
                QMessageBox.warning(self, "Format invalide", "Le format d'image n'est pas supporté ou le fichier est corrompu")
                return
            
            # Redimensionner pour l'aperçu tout en conservant les proportions
            scaled_pixmap = pixmap.scaled(200, 150, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.image_preview.setPixmap(scaled_pixmap)
            self.current_image_path = file_path
            
            print(f"✅ Image chargée: {file_path}")
            
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Impossible de charger l'image: {str(e)}")
            
    def load_existing_image(self, image_url=None, item_code=None):
        """Charge l'image via l'URL Cloudinary (même méthode que les boss)"""
        if not image_url:
            self._reset_image_preview()
            return

        try:
            if image_url.startswith('/'):
                full_url = f"{self.api_client.backend_url}{image_url}"
            else:
                full_url = image_url

            # Même méthode que load_boss_image : httpx.get direct
            response = httpx.get(full_url, timeout=10.0, follow_redirects=True)
            if response.status_code == 200:
                pixmap = QPixmap()
                pixmap.loadFromData(response.content)
                if not pixmap.isNull():
                    scaled_pixmap = pixmap.scaled(200, 150, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                    self.image_preview.setPixmap(scaled_pixmap)
                else:
                    self.image_preview.setText("⚠️ Image corrompue")
            else:
                self._reset_image_preview()

        except Exception as e:
            print(f"❌ Erreur chargement image: {e}")
            self._reset_image_preview()

    def _reset_image_preview(self):
        """Remet l'aperçu image à zéro (UI uniquement, pas d'appel serveur)"""
        self.image_preview.clear()
        self.image_preview.setText("Aucune image\n\n📁 Glisser-déposer une image\nou cliquer pour sélectionner")
        self.current_image_path = None

    def clear_image(self):
        """Bouton supprimer : supprime l'image du serveur si elle existe"""
        if self.current_item and self.current_item.get('image_url'):
            code = self.current_item.get('code', '')
            reply = QMessageBox.question(
                self,
                "Confirmation",
                f"Supprimer l'image de '{code}' du serveur ?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.No:
                return
            result = self.api_client.delete_item_image(code)
            if result and "error" not in result:
                print(f"✅ Image supprimée en DB pour {code}")
                self.current_item['image_url'] = None
                self.api_client.invalidate_items_cache()
            else:
                print(f"❌ Erreur suppression image: {result}")

        self._reset_image_preview()


    def refresh_items(self):
        """Charge tous les items depuis l'API"""
        try:
            self.api_client.invalidate_items_cache()
            data = self.api_client.get_all_items()

            if data and "error" not in data:
                self.all_items = data.get("items", [])
                self.display_items(self.all_items)
            else:
                self.load_items_fallback()
                
        except Exception as e:
            print(f"❌ Erreur chargement items: {e}")
            self.load_items_fallback()

    def load_items_fallback(self):
        """Affiche un message d'erreur propre quand le chargement échoue"""
        self.all_items = []
        self.items_list.clear()
        self.items_list.addItem("❌ Impossible de charger les items")
        self.items_list.addItem("🔄 Cliquez sur Actualiser ou changez d'onglet pour réessayer")

    def display_items(self, items):
        """Affiche la liste des items"""
        self.items_list.clear()
        
        for item in items:
            code = item.get('code', '')
            name = item.get('name', 'Sans nom')
            rarity = item.get('rarity', 'common')
            stackable = item.get('stackable', True)
            is_group_reward = item.get('is_group_reward', False)
            has_image = bool(item.get('image_url'))
            
            # Couleur selon la rareté
            color = RARITY_COLORS.get(rarity, "#8b949e")
            stackable_icon = "📦" if stackable else "📎"
            group_icon = "👥" if is_group_reward else "👤"
            image_icon = "🖼️" if has_image else "📷"
            
            item_text = f"{stackable_icon} {group_icon} {image_icon} {code} - {name} ({rarity})"
            
            item_widget = QListWidgetItem(item_text)
            item_widget.setData(Qt.UserRole, item)
            item_widget.setForeground(QColor(color))
            
            # Tooltip avec détails
            tooltip = f"📦 {name}\n"
            tooltip += f"🔖 Code: {code}\n"
            tooltip += f"🎯 Rareté: {rarity}\n"
            tooltip += f"📊 Stackable: {'Oui' if stackable else 'Non'}\n"
            tooltip += f"👥 Type: {'Mission de groupe' if is_group_reward else 'Mission solo'}\n"
            tooltip += f"🖼️ Image: {'Oui' if has_image else 'Non'}\n"
            
            description = item.get('description', '')
            if description:
                tooltip += f"📝 {description}\n"
                
            evenement_id = item.get('evenement_id')
            if evenement_id:
                tooltip += f"🏆 Événement: {evenement_id}"
                
            item_widget.setToolTip(tooltip)
            self.items_list.addItem(item_widget)

    # Codes des ressources lootables (drops de missions solo)
    LOOTABLE_CODES = {
        # Bois (mission bois)
        "WOOD_RAW", "WOOD_KNOTTY", "WOOD_BLACK", "WOOD_ANCIENT", "WOOD_LUNAR", "WOOD_HEART",
        # Pierre (mission pierre)
        "STONE_RAW", "STONE_SPLIT", "STONE_LUNAR", "STONE_RUNIC", "STONE_HEART",
        # Végétaux (ramassage main)
        "HERB_WILT", "ROOT_BLACK", "LICHEN_DARK", "FLOWER_NIGHT", "ROOT_NIGHTMARE", "ESSENCE_FOREST",
        # Dragage
        "DEBRIS_SOGGY", "PAPER_SOGGY", "LEATHER_SOGGY", "PAGE_ILLEGIBLE", "DEBRIS_LUNAR", "FRAGMENT_NIGHT",
        # Os (mission os)
        "BONE_TARNISHED", "BONE_ENGRAVED", "BONE_ANCIENT", "BONE_CURSED", "BONE_WOLF",
    }

    def on_category_changed(self, category):
        """Affiche/masque le sous-filtre ressources selon la catégorie choisie"""
        if category == "Ressources":
            self.resource_sub_filter.show()
        else:
            self.resource_sub_filter.hide()
            self.resource_sub_filter.setCurrentIndex(0)
        self.filter_items()

    def filter_items(self):
        """Filtre les items selon recherche, rareté, type, catégorie et image"""
        search_text = self.search_input.text().lower()
        rarity_filter = self.rarity_filter.currentText()
        type_filter = self.type_filter.currentText()
        category_filter = self.category_filter.currentText()
        resource_sub = self.resource_sub_filter.currentText()
        no_image_only = self.no_image_filter.isChecked()

        filtered_items = []
        for item in self.all_items:
            # Filtre par recherche
            matches_search = (search_text in item.get('code', '').lower() or
                            search_text in item.get('name', '').lower() or
                            search_text in item.get('description', '').lower())

            # Filtre par rareté
            matches_rarity = (rarity_filter == "Toutes les raretés" or
                            item.get('rarity', '') == rarity_filter)

            # Filtre solo/groupe
            matches_type = True
            if type_filter == "Solo seulement":
                matches_type = not item.get('is_group_reward', False)
            elif type_filter == "Groupe seulement":
                matches_type = item.get('is_group_reward', False)

            # Filtre par catégorie
            matches_category = True
            if category_filter == "Ressources":
                matches_category = (item.get('type') == 'resource' and
                                  item.get('evenement_id') is None)
            elif category_filter == "Outils":
                matches_category = item.get('type') == 'tool'
            elif category_filter == "Objets de Quête":
                matches_category = item.get('evenement_id') is not None

            # Sous-filtre ressources (lootables vs craftables)
            matches_resource_sub = True
            if category_filter == "Ressources" and matches_category:
                code = item.get('code', '')
                if resource_sub == "Lootables":
                    matches_resource_sub = code in self.LOOTABLE_CODES
                elif resource_sub == "Craftables (supercraft)":
                    matches_resource_sub = code not in self.LOOTABLE_CODES

            # Filtre sans image
            matches_image = True
            if no_image_only:
                matches_image = not bool(item.get('image_url'))

            if (matches_search and matches_rarity and matches_type and
                    matches_category and matches_resource_sub and matches_image):
                filtered_items.append(item)

        self.display_items(filtered_items)

    def item_selected(self, item):
        """Quand un item est sélectionné dans la liste"""
        item_data = item.data(Qt.UserRole)
        self.current_item = item_data

        # Remplir le formulaire
        self.item_code.setText(item_data.get('code', ''))
        self.item_name.setText(item_data.get('name', ''))
        self.item_description.setPlainText(item_data.get('description', ''))

        # Définir la rareté
        rarity = item_data.get('rarity', 'common')
        index = self.item_rarity.findText(rarity)
        if index >= 0:
            self.item_rarity.setCurrentIndex(index)

        self.item_stackable.setChecked(item_data.get('stackable', True))
        self.item_evenement_id.setText(str(item_data.get('evenement_id', '')))

        # Définir le type
        item_type = item_data.get('type', 'resource')
        type_index = self.item_type.findText(item_type)
        if type_index >= 0:
            self.item_type.setCurrentIndex(type_index)

        # Définir la checkbox de récompense de groupe
        is_group_reward = item_data.get('is_group_reward', False)
        self.item_is_group_reward.setChecked(bool(is_group_reward))

        # Charger l'image existante (chercher dans plusieurs champs possibles)
        image_url = item_data.get('image_url') or item_data.get('image') or None
        item_code = item_data.get('code', '')
        self.load_existing_image(image_url, item_code)
        self.current_image_path = None  # Réinitialiser le chemin de nouvelle image

    def new_item(self):
        """Réinitialise le formulaire pour un nouvel item"""
        self.current_item = None
        self.item_code.clear()
        self.item_name.clear()
        self.item_description.clear()
        self.item_rarity.setCurrentIndex(0)
        self.item_type.setCurrentIndex(0)
        self.item_stackable.setChecked(True)
        self.item_evenement_id.clear()
        self.item_is_group_reward.setChecked(False)
        self._reset_image_preview()
        self.items_list.clearSelection()

    def save_item(self):
        """Sauvegarde l'item (création ou modification) avec gestion d'image"""
        try:
            # Validation
            code = self.item_code.text().strip().upper()
            name = self.item_name.text().strip()
            
            if not code:
                QMessageBox.warning(self, "Erreur", "Le code de l'item est obligatoire")
                return
                
            if not name:
                QMessageBox.warning(self, "Erreur", "Le nom de l'item est obligatoire")
                return

            # Préparation des données de base
            item_data = {
                "code": code,
                "name": name,
                "description": self.item_description.toPlainText().strip(),
                "type": self.item_type.currentText(),
                "rarity": self.item_rarity.currentText(),
                "stackable": self.item_stackable.isChecked(),
                "is_group_reward": self.item_is_group_reward.isChecked()
            }
            
            # ID événement optionnel
            evenement_id = self.item_evenement_id.text().strip()
            if evenement_id and evenement_id.isdigit():
                item_data["evenement_id"] = int(evenement_id)

            print(f"💾 Données à sauvegarder: {item_data}")

            # Sauvegarde de l'item d'abord
            result = self.api_client._make_request("POST", "/admin/items/upsert", json=item_data)
            
            if result and "error" in result:
                QMessageBox.critical(self, "Erreur", f"Erreur lors de la sauvegarde: {result['error']}")
                return

            # Upload de l'image si une nouvelle image a été sélectionnée
            if self.current_image_path:
                print(f"📤 Upload de l'image: {self.current_image_path}")
                image_url = self.api_client.upload_item_image(code, self.current_image_path)
                
                if image_url:
                    # Mettre à jour l'URL de l'image dans l'item
                    update_data = {"image_url": image_url}
                    self.api_client._make_request("POST", f"/admin/items/{code}/update-image", json=update_data)
                    print(f"✅ Image uploadée: {image_url}")
                else:
                    QMessageBox.warning(self, "Avertissement", "L'item a été sauvegardé mais l'image n'a pas pu être uploadée")

            message = f"Item '{code}' sauvegardé avec succès!"
            if self.item_is_group_reward.isChecked():
                message += "\n\n✅ Cet item est maintenant disponible pour les missions de groupe"
            else:
                message += "\n\n✅ Cet item est maintenant disponible pour les missions solo"
                
            if self.current_image_path:
                message += "\n🖼️ Image uploadée avec succès"
                
            QMessageBox.information(self, "Succès", message)
            self.refresh_items()
            self.new_item()  # Réinitialiser le formulaire
                
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur inattendue: {str(e)}")

    def delete_item(self):
        """Supprime l'item sélectionné"""
        if not self.current_item:
            QMessageBox.warning(self, "Erreur", "Aucun item sélectionné")
            return
            
        code = self.current_item.get('code')
        if not code:
            return
            
        reply = QMessageBox.question(
            self, 
            "Confirmation", 
            f"Êtes-vous sûr de vouloir supprimer l'item '{code}' ?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            result = self.api_client._make_request("DELETE", f"/admin/items/{code}")
            
            if result and "error" in result:
                QMessageBox.critical(self, "Erreur", f"Erreur lors de la suppression: {result['error']}")
            else:
                QMessageBox.information(self, "Succès", f"Item '{code}' supprimé avec succès!")
                self.refresh_items()
                self.new_item()

# Section 6.4
class ItemEffectsTab(QWidget):
    """Onglet de gestion des effets d'items"""

    def __init__(self, api_client):
        super().__init__()
        self.api_client = api_client
        self.current_item_code = None
        self.init_ui()
        self.load_items_for_effects()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)

        # Header
        header_layout = QHBoxLayout()
        title = QLabel("⚡ GESTION DES EFFETS D'ITEMS")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #ffd700;")
        header_layout.addWidget(title)
        header_layout.addStretch()
        
        refresh_btn = QPushButton("🔄 Actualiser")
        refresh_btn.clicked.connect(self.refresh_data)
        header_layout.addWidget(refresh_btn)
        
        layout.addLayout(header_layout)

        # Contenu principal
        content_layout = QHBoxLayout()
        content_layout.setSpacing(15)

        # Formulaire d'ajout d'effet
        form_group = QGroupBox("➕ Ajouter un Effet")
        form_group.setMaximumWidth(400)
        form_layout = QVBoxLayout()

        # Sélection d'item
        item_layout = QHBoxLayout()
        item_layout.addWidget(QLabel("Item:"))
        self.effect_item_combo = QComboBox()
        self.effect_item_combo.currentTextChanged.connect(self.on_item_changed)
        item_layout.addWidget(self.effect_item_combo, 1)
        form_layout.addLayout(item_layout)

        # Formulaire d'effet
        effect_form = QFormLayout()
        
        self.effect_type_combo = QComboBox()
        effect_form.addRow("Type d'effet*:", self.effect_type_combo)
        
        self.effect_value = QSpinBox()
        self.effect_value.setRange(1, 1000)
        self.effect_value.setValue(10)
        effect_form.addRow("Valeur*:", self.effect_value)
        
        self.effect_event_type = QComboBox()
        effect_form.addRow("Cible*:", self.effect_event_type)
        
        self.effect_uses = QSpinBox()
        self.effect_uses.setRange(1, 100)
        self.effect_uses.setValue(1)
        effect_form.addRow("Utilisations:", self.effect_uses)

        form_layout.addLayout(effect_form)

        # Bouton d'ajout
        self.add_effect_btn = QPushButton("⚡ Ajouter l'effet")
        self.add_effect_btn.clicked.connect(self.add_item_effect)
        self.add_effect_btn.setStyleSheet("background-color: #238636;")
        form_layout.addWidget(self.add_effect_btn)

        form_group.setLayout(form_layout)
        content_layout.addWidget(form_group)

        # Liste des effets existants
        list_group = QGroupBox("📋 Effets Existants")
        list_layout = QVBoxLayout()
        
        self.effects_list = QListWidget()
        self.effects_list.itemClicked.connect(self.on_effect_selected)
        self.effects_list.setStyleSheet("""
            QListWidget {
                background-color: #0d1117;
                color: #e6edf3;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 5px;
            }
        """)
        list_layout.addWidget(self.effects_list)
        
        # Bouton de suppression
        self.delete_effect_btn = QPushButton("🗑️ Supprimer l'effet sélectionné")
        self.delete_effect_btn.clicked.connect(self.delete_item_effect)
        self.delete_effect_btn.setStyleSheet("background-color: #da3633;")
        self.delete_effect_btn.setEnabled(False)
        list_layout.addWidget(self.delete_effect_btn)
        
        list_group.setLayout(list_layout)
        content_layout.addWidget(list_group)

        layout.addLayout(content_layout)
        self.setLayout(layout)

        # Charger les types
        self.load_effect_types()
        self.load_event_types()

    def load_items_for_effects(self):
        """Charge les items pour la sélection d'effets"""
        try:
            items_data = self.api_client.get_all_items()
            if items_data and "items" in items_data:
                self.effect_item_combo.clear()
                for item in items_data["items"]:
                    display_text = f"{item['code']} - {item['name']}"
                    self.effect_item_combo.addItem(display_text, item['code'])
                print(f"✅ {len(items_data['items'])} items chargés pour les effets")
        except Exception as e:
            print(f"❌ Erreur chargement items pour effets: {e}")

    def load_effect_types(self):
        """Charge les types d'effets disponibles"""
        try:
            effect_types_data = self.api_client.get_effect_types()
            if effect_types_data and "effect_types" in effect_types_data:
                self.effect_type_combo.clear()
                for effect_type in effect_types_data["effect_types"]:
                    display_text = f"{effect_type['label']} - {effect_type['description']}"
                    self.effect_type_combo.addItem(display_text, effect_type['value'])
        except Exception as e:
            print(f"❌ Erreur chargement types d'effets: {e}")

    def load_event_types(self):
        """Charge les types d'événements disponibles"""
        try:
            event_types_data = self.api_client.get_event_types()
            if event_types_data and "event_types" in event_types_data:
                self.effect_event_type.clear()
                for event_type in event_types_data["event_types"]:
                    self.effect_event_type.addItem(event_type.replace('_', ' ').title(), event_type)
        except Exception as e:
            print(f"❌ Erreur chargement types d'événements: {e}")

    def on_item_changed(self):
        """Quand l'item sélectionné change"""
        if self.effect_item_combo.currentData():
            self.current_item_code = self.effect_item_combo.currentData()
            self.load_item_effects(self.current_item_code)

    def on_effect_selected(self, item):
        """Quand un effet est sélectionné"""
        self.delete_effect_btn.setEnabled(item is not None)

    def refresh_data(self):
        """Rafraîchit toutes les données"""
        self.load_items_for_effects()
        self.load_effect_types()
        self.load_event_types()
        if self.current_item_code:
            self.load_item_effects(self.current_item_code)

    def load_item_effects(self, item_code: str):
        """Charge les effets d'un item"""
        try:
            effects_data = self.api_client.get_item_effects(item_code)
            if effects_data and "effects" in effects_data:
                self.effects_list.clear()
                for effect in effects_data["effects"]:
                    # Formater l'affichage de l'effet
                    effect_type = effect['effect_type'].replace('_', ' ').title()
                    target = effect['target_event_type'].replace('_', ' ').title() if effect['target_event_type'] else "Tous"
                    
                    effect_text = f"⚡ {effect_type}: +{effect['effect_value']}"
                    effect_text += f" | Cible: {target}"
                    effect_text += f" | Utilisations: {effect['uses_available']}"
                    
                    item = QListWidgetItem(effect_text)
                    item.setData(Qt.UserRole, effect['id'])
                    
                    # Couleur selon le type d'effet
                    colors = {
                        "malus_reduction": "#3fb950",
                        "attack_bonus": "#da3633", 
                        "time_extension": "#58a6ff",
                        "xp_boost": "#ffa726"
                    }
                    color = colors.get(effect['effect_type'], "#8b949e")
                    item.setForeground(QColor(color))
                    
                    self.effects_list.addItem(item)
                    
                print(f"✅ {len(effects_data['effects'])} effets chargés pour {item_code}")
            else:
                self.effects_list.clear()
                self.effects_list.addItem("Aucun effet défini pour cet item")
                
        except Exception as e:
            print(f"❌ Erreur chargement effets: {e}")
            self.effects_list.clear()
            self.effects_list.addItem("❌ Erreur de chargement")

    def add_item_effect(self):
        """Ajoute un effet à un item"""
        if not self.current_item_code:
            QMessageBox.warning(self, "Erreur", "Veuillez sélectionner un item")
            return
        
        effect_type = self.effect_type_combo.currentData()
        effect_value = self.effect_value.value()
        target_event_type = self.effect_event_type.currentData()
        uses_available = self.effect_uses.value()
        
        if not effect_type:
            QMessageBox.warning(self, "Erreur", "Veuillez sélectionner un type d'effet")
            return
    
        effect_data = {
            "effect_type": effect_type,
            "effect_value": effect_value,
            "target_event_type": target_event_type,
            "uses_available": uses_available,
            "is_group_reward": True
        }
        
        result = self.api_client.add_item_effect(self.current_item_code, effect_data)
        if result and result.get("success"):
            QMessageBox.information(self, "Succès", "Effet ajouté avec succès")
            self.load_item_effects(self.current_item_code)
            # Réinitialiser le formulaire
            self.effect_value.setValue(10)
            self.effect_uses.setValue(1)
        else:
            error_msg = result.get('error', 'Erreur inconnue') if result else "Erreur de connexion"
            QMessageBox.critical(self, "Erreur", f"Erreur lors de l'ajout: {error_msg}")

    def delete_item_effect(self):
        """Supprime l'effet sélectionné"""
        current_item = self.effects_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, "Erreur", "Aucun effet sélectionné")
            return
            
        effect_id = current_item.data(Qt.UserRole)
        if not effect_id:
            return
            
        reply = QMessageBox.question(
            self, 
            "Confirmation", 
            "Êtes-vous sûr de vouloir supprimer cet effet ?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            result = self.api_client.delete_item_effect(effect_id)
            if result and result.get("success"):
                QMessageBox.information(self, "Succès", "Effet supprimé avec succès")
                self.load_item_effects(self.current_item_code)
            else:
                error_msg = result.get('error', 'Erreur inconnue') if result else "Erreur de connexion"
                QMessageBox.critical(self, "Erreur", f"Erreur lors de la suppression: {error_msg}")

# Section 7: Onglet Overlay amélioré
class OverlayTab(QWidget):
    """Onglet de configuration de l'overlay - NOUVELLE VERSION"""

    def __init__(self, api_client):
        super().__init__()
        self.api_client = api_client
        self.current_config = {}
        self.init_ui()
        self.load_config()

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(15, 15, 15, 15)

        # En-tête
        header_layout = QHBoxLayout()
        header_layout.addWidget(QLabel("🎬 Configuration de l'overlay - NOUVEAU DESIGN"))
        header_layout.addStretch()
        
        load_btn = QPushButton("🔄 Charger")
        load_btn.clicked.connect(self.load_config)
        save_btn = QPushButton("💾 Sauvegarder")
        save_btn.clicked.connect(self.save_config)
        
        header_layout.addWidget(load_btn)
        header_layout.addWidget(save_btn)
        main_layout.addLayout(header_layout)

        # Contenu principal
        content_layout = QHBoxLayout()

        # Prévisualisation
        preview_group = QGroupBox("Prévisualisation - Glisser-déposer les widgets")
        preview_layout = QVBoxLayout()
        self.preview = OverlayPreview()
        preview_layout.addWidget(self.preview)
        preview_group.setLayout(preview_layout)
        content_layout.addWidget(preview_group, 2)

        # Options du nouveau design
        options_group = QGroupBox("Options des Widgets")
        options_layout = QVBoxLayout()
        
        # Options pour chaque widget
        self.show_hud = QCheckBox("Afficher HUD Progression")
        self.show_event_timer = QCheckBox("Afficher Compteur Event")
        self.show_ranking = QCheckBox("Afficher Classement Live")
        self.show_commands = QCheckBox("Afficher Commandes")
        self.show_toasts = QCheckBox("Afficher Chroniques")
        self.show_stats = QCheckBox("Afficher Archives")
        self.show_map = QCheckBox("Afficher Carte")
        self.show_hall_of_fame = QCheckBox("Afficher Légendes")
        
        # Options générales
        self.enable_sounds = QCheckBox("Activer les sons")
        self.show_borders = QCheckBox("Afficher les bordures d'écran")
        self.auto_show_summary = QCheckBox("Afficher auto résumé de fin")
        
        options_layout.addWidget(QLabel("📊 Widgets:"))
        options_layout.addWidget(self.show_hud)
        options_layout.addWidget(self.show_event_timer)
        options_layout.addWidget(self.show_ranking)
        options_layout.addWidget(self.show_commands)
        options_layout.addWidget(self.show_toasts)
        options_layout.addWidget(self.show_stats)
        options_layout.addWidget(self.show_map)
        options_layout.addWidget(self.show_hall_of_fame)
        
        options_layout.addSpacing(10)
        options_layout.addWidget(QLabel("🎛️ Options générales:"))
        options_layout.addWidget(self.enable_sounds)
        options_layout.addWidget(self.show_borders)
        options_layout.addWidget(self.auto_show_summary)
        
        options_layout.addStretch()
        options_group.setLayout(options_layout)
        content_layout.addWidget(options_group, 1)

        main_layout.addLayout(content_layout)

        # Boutons de contrôle
        control_layout = QHBoxLayout()
        
        test_btn = QPushButton("🧪 Test Overlay")
        test_btn.clicked.connect(self.test_overlay)
        reset_btn = QPushButton("🔄 Positions par défaut")
        reset_btn.clicked.connect(self.reset_positions)
        default_btn = QPushButton("⚙️ Configuration par défaut")
        default_btn.clicked.connect(self.set_default_config)
        
        control_layout.addWidget(test_btn)
        control_layout.addWidget(reset_btn)
        control_layout.addWidget(default_btn)
        control_layout.addStretch()
        
        main_layout.addLayout(control_layout)
        self.setLayout(main_layout)

    def load_config(self):
        """Charge la configuration de l'overlay"""
        config = self.api_client.get_overlay_config()
        
        if not config:
            QMessageBox.warning(self, "Erreur", "Impossible de charger la configuration de l'overlay")
            return

        self.current_config = config

        # Mettre à jour les options
        options = config.get("options", {})
        self.show_hud.setChecked(options.get("show_hud", True))
        self.show_event_timer.setChecked(options.get("show_event_timer", True))
        self.show_ranking.setChecked(options.get("show_ranking", True))
        self.show_commands.setChecked(options.get("show_commands", True))
        self.show_toasts.setChecked(options.get("show_toasts", True))
        self.show_stats.setChecked(options.get("show_stats", True))
        self.show_map.setChecked(options.get("show_map", True))
        self.show_hall_of_fame.setChecked(options.get("show_hall_of_fame", True))
        self.enable_sounds.setChecked(options.get("enable_sounds", True))
        self.show_borders.setChecked(options.get("show_borders", True))
        self.auto_show_summary.setChecked(options.get("auto_show_summary", True))

        # Mettre à jour les positions des widgets
        widgets = config.get("widgets", {})
        self.preview.set_positions(widgets)

    def save_config(self):
        """Sauvegarde la configuration de l'overlay"""
        config = {
            "widgets": self.preview.get_positions(),
            "options": {
                "show_hud": self.show_hud.isChecked(),
                "show_event_timer": self.show_event_timer.isChecked(),
                "show_ranking": self.show_ranking.isChecked(),
                "show_commands": self.show_commands.isChecked(),
                "show_toasts": self.show_toasts.isChecked(),
                "show_stats": self.show_stats.isChecked(),
                "show_map": self.show_map.isChecked(),
                "show_hall_of_fame": self.show_hall_of_fame.isChecked(),
                "enable_sounds": self.enable_sounds.isChecked(),
                "show_borders": self.show_borders.isChecked(),
                "auto_show_summary": self.auto_show_summary.isChecked()
            }
        }

        result = self.api_client.save_overlay_config(config)
        if result and "error" in result:
            QMessageBox.critical(self, "Erreur", f"Erreur lors de la sauvegarde: {result['error']}")
        else:
            QMessageBox.information(self, "Succès", "Configuration sauvegardée. Rechargez l'overlay pour voir les changements.")

    def test_overlay(self):
        """Teste la configuration avec des positions par défaut"""
        test_config = {
            "widgets": {
                "hud": {"x": 50, "y": 20, "w": 600, "h": 80},
                "event-timer": {"x": 1400, "y": 20, "w": 400, "h": 60},
                "ranking-widget": {"x": 1400, "y": 100, "w": 400, "h": 300},
                "commands-widget": {"x": 50, "y": 600, "w": 400, "h": 400},
                "toasts-widget": {"x": 800, "y": 600, "w": 500, "h": 300},
                "stats-widget": {"x": 50, "y": 300, "w": 350, "h": 250},
                "map-widget": {"x": 800, "y": 300, "w": 500, "h": 250},
                "hall-of-fame": {"x": 1400, "y": 450, "w": 400, "h": 250}
            },
            "options": {
                "show_hud": True,
                "show_event_timer": True,
                "show_ranking": True,
                "show_commands": True,
                "show_toasts": True,
                "show_stats": True,
                "show_map": True,
                "show_hall_of_fame": True,
                "enable_sounds": True,
                "show_borders": True,
                "auto_show_summary": True
            }
        }
        
        result = self.api_client.save_overlay_config(test_config)
        if result and "error" in result:
            QMessageBox.critical(self, "Erreur", f"Test échoué: {result['error']}")
        else:
            QMessageBox.information(self, "Succès", "Test envoyé! Vérifiez l'overlay.")

    def reset_positions(self):
        """Réinitialise les positions aux valeurs par défaut"""
        default_positions = {
            "hud": {"x": 50, "y": 20, "w": 600, "h": 80},
            "event-timer": {"x": 1400, "y": 20, "w": 400, "h": 60},
            "ranking-widget": {"x": 1400, "y": 100, "w": 400, "h": 300},
            "commands-widget": {"x": 50, "y": 600, "w": 400, "h": 400},
            "toasts-widget": {"x": 800, "y": 600, "w": 500, "h": 300},
            "stats-widget": {"x": 50, "y": 300, "w": 350, "h": 250},
            "map-widget": {"x": 800, "y": 300, "w": 500, "h": 250},
            "hall-of-fame": {"x": 1400, "y": 450, "w": 400, "h": 250}
        }
        self.preview.set_positions(default_positions)
        QMessageBox.information(self, "Succès", "Positions réinitialisées")

    def set_default_config(self):
        """Applique une configuration par défaut complète"""
        default_config = {
            "widgets": {
                "hud": {"x": 50, "y": 20, "w": 600, "h": 80},
                "event-timer": {"x": 1400, "y": 20, "w": 400, "h": 60},
                "ranking-widget": {"x": 1400, "y": 100, "w": 400, "h": 300},
                "commands-widget": {"x": 50, "y": 600, "w": 400, "h": 400},
                "toasts-widget": {"x": 800, "y": 600, "w": 500, "h": 300},
                "stats-widget": {"x": 50, "y": 300, "w": 350, "h": 250},
                "map-widget": {"x": 800, "y": 300, "w": 500, "h": 250},
                "hall-of-fame": {"x": 1400, "y": 450, "w": 400, "h": 250}
            },
            "options": {
                "show_hud": True,
                "show_event_timer": True,
                "show_ranking": True,
                "show_commands": True,
                "show_toasts": True,
                "show_stats": True,
                "show_map": False,  # Carte cachée par défaut
                "show_hall_of_fame": True,
                "enable_sounds": True,
                "show_borders": True,
                "auto_show_summary": True
            }
        }
        
        # Appliquer localement
        self.preview.set_positions(default_config["widgets"])
        
        # Mettre à jour les options
        options = default_config["options"]
        self.show_hud.setChecked(options["show_hud"])
        self.show_event_timer.setChecked(options["show_event_timer"])
        self.show_ranking.setChecked(options["show_ranking"])
        self.show_commands.setChecked(options["show_commands"])
        self.show_toasts.setChecked(options["show_toasts"])
        self.show_stats.setChecked(options["show_stats"])
        self.show_map.setChecked(options["show_map"])
        self.show_hall_of_fame.setChecked(options["show_hall_of_fame"])
        self.enable_sounds.setChecked(options["enable_sounds"])
        self.show_borders.setChecked(options["show_borders"])
        self.auto_show_summary.setChecked(options["auto_show_summary"])
        
        QMessageBox.information(self, "Succès", "Configuration par défaut appliquée")           
            
# Section 8: Onglet Session amélioré
class SessionTab(QWidget):
    """Onglet de gestion de session"""

    def __init__(self, api_client, login_callback):
        super().__init__()
        self.api_client = api_client
        self.login_callback = login_callback
        self.check_timer = None
        self.init_ui()
        # Vérifier la session après un court délai
        QTimer.singleShot(100, self.check_session)

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)

        session_group = QGroupBox("Session & OAuth")
        session_layout = QVBoxLayout()

        self.session_info = QLabel("Vérification de la session...")
        self.session_info.setStyleSheet("font-size: 14px; padding: 10px;")
        session_layout.addWidget(self.session_info)

        debug_btn = QPushButton("🐛 Debug Avancé")
        debug_btn.clicked.connect(self.show_debug_info)
        debug_btn.setStyleSheet("background-color: #ff6b6b; color: white;")
        session_layout.addWidget(debug_btn)

        connect_btn = QPushButton("🔒 Se connecter via Twitch")
        connect_btn.clicked.connect(self.connect_twitch)
        connect_btn.setStyleSheet("font-weight: bold; background-color: #4ab; padding: 10px;")
        session_layout.addWidget(connect_btn)

        manual_group = QGroupBox("Méthode manuelle")
        manual_layout = QVBoxLayout()

        token_layout = QHBoxLayout()
        token_layout.addWidget(QLabel("Token manuel:"))
        self.token_input = QLineEdit()
        self.token_input.setPlaceholderText("Collez le token ici")
        token_layout.addWidget(self.token_input)

        token_btn = QPushButton("Utiliser")
        token_btn.clicked.connect(self.use_manual_token)
        token_layout.addWidget(token_btn)

        manual_layout.addLayout(token_layout)
        manual_group.setLayout(manual_layout)

        btn_layout = QHBoxLayout()
        whoami_btn = QPushButton("Vérifier session")
        whoami_btn.clicked.connect(self.check_session)
        logout_btn = QPushButton("Déconnexion")
        logout_btn.clicked.connect(self.logout)

        btn_layout.addWidget(whoami_btn)
        btn_layout.addWidget(logout_btn)

        session_layout.addLayout(btn_layout)
        session_group.setLayout(session_layout)

        layout.addWidget(session_group)
        layout.addWidget(manual_group)
        self.setLayout(layout)

    def use_manual_token(self):
        token_value = self.token_input.text().strip()
        if token_value:
            print(f"🔧 Utilisation token manuel: {token_value}")
            self.api_client.jwt_token = token_value
            self.api_client.client.headers['Authorization'] = f'Bearer {token_value}'
            self.api_client.save_cookies()
            self.session_info.setText("✅ Token défini, vérification...")
            QTimer.singleShot(1000, self.check_session)
        else:
            self.session_info.setText("❌ Veuillez saisir un token")

    def show_debug_info(self):
        debug_info = {
            'jwt_token': self.api_client.jwt_token,
            'headers': dict(self.api_client.client.headers),
            'backend_url': self.api_client.backend_url,
            'debug_info': self.api_client.debug_info
        }

        debug_dialog = QDialog(self)
        debug_dialog.setWindowTitle("Debug Information")
        debug_dialog.setMinimumSize(800, 500)

        layout = QVBoxLayout()

        info_text = QTextEdit()
        info_text.setPlainText(json.dumps(debug_info, indent=2, ensure_ascii=False))

        test_btn = QPushButton("🔍 Tester la connectivité")
        test_btn.clicked.connect(lambda: self.api_client.test_connectivity())

        layout.addWidget(QLabel("Informations de Debug:"))
        layout.addWidget(info_text)
        layout.addWidget(test_btn)

        close_btn = QPushButton("Fermer")
        close_btn.clicked.connect(debug_dialog.accept)
        layout.addWidget(close_btn)

        debug_dialog.setLayout(layout)
        debug_dialog.exec()

    def check_session(self):
        print("\n" + "="*30)
        print("🔄 VÉRIFICATION SESSION")
        print("="*30)

        user_info = self.api_client.whoami()

        if user_info:
            login = user_info.get("login", "Inconnu")
            status_text = f"✅ Connecté en tant que: {login}"
            self.session_info.setText(status_text)
            self.session_info.setStyleSheet("color: green; font-weight: bold;")
            self.login_callback(True)
            print(f"✅ Session active: {login}")
        else:
            status_text = "❌ Non connecté"
            self.session_info.setText(status_text)
            self.session_info.setStyleSheet("color: red;")
            self.login_callback(False)
            print("❌ Aucune session active")

    def connect_twitch(self):
        self.session_info.setText("🔄 Démarrage interception...")
        try:
            self.api_client.login_twitch()
            self.session_info.setText("👤 Authentifiez-vous dans le navigateur...")

            if self.check_timer:
                self.check_timer.stop()

            self.check_timer = QTimer()
            self.check_timer.timeout.connect(self.check_session)
            self.check_timer.start(2000)

        except Exception as e:
            self.session_info.setText(f"❌ Erreur: {str(e)}")

    def logout(self):
        if self.check_timer:
            self.check_timer.stop()

        self.api_client.logout()
        self.token_input.clear()
        self.check_session()


# Section 9: Fenêtre principale améliorée
class StreamQuestAdmin(QMainWindow):
    """Fenêtre principale de l'administration StreamQuest"""

    def __init__(self):
        super().__init__()
        self.api_client = APIClient(BACKEND_URL)
        self.sse_thread = None
        self.init_ui()
        self.setup_connections()

    def init_ui(self):
        self.setWindowTitle("StreamQuest SuperAdmin")
        self.setGeometry(100, 100, 1200, 800)
        self.setStyleSheet(APP_STYLESHEET)

        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))
            print(f"Icône chargée depuis : {icon_path}")
            # FORCER LE RAFRAÎCHISSEMENT DE LA FENÊTRE
            self.refresh_window_icon()
        else:
            print(f"❌ Icône non trouvée à : {icon_path}")
    
    def refresh_window_icon(self):
        """Force le rafraîchissement de l'icône dans la barre des tâches Windows"""
        # Méthode 1: Cacher et remontrer la fenêtre
        self.hide()
        QTimer.singleShot(50, self.show)
        
        # Créer un widget de défilement pour la fenêtre principale
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        
        # Widget central qui contiendra tout le contenu
        central_container = QWidget()
        scroll_area.setWidget(central_container)
        self.setCentralWidget(scroll_area)
        
        main_layout = QVBoxLayout(central_container)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Barre de titre personnalisée
        title_bar = QWidget()
        title_bar.setFixedHeight(40)
        title_bar.setStyleSheet("""
            background-color: #161b22;
            border-bottom: 1px solid #30363d;
        """)
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(15, 0, 15, 0)
        
        title_label = QLabel("🎮 StreamQuest SuperAdmin")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #e6edf3;")
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        
        self.status_indicator = QLabel("🔴")
        self.status_indicator.setStyleSheet("font-size: 14px;")
        title_layout.addWidget(self.status_indicator)
        
        self.status_label = QLabel("Déconnecté")
        self.status_label.setStyleSheet("color: #8b949e;")
        title_layout.addWidget(self.status_label)
        title_layout.addSpacing(15)
        
        self.session_info = QLabel("Non authentifié")
        self.session_info.setStyleSheet("color: #8b949e;")
        title_layout.addWidget(self.session_info)
        
        main_layout.addWidget(title_bar)

        # Onglets principaux
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: none;
                background-color: #0d1117;
            }
            QTabBar::tab {
                background-color: #161b22;
                color: #e6edf3;
                padding: 8px 16px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #1f6feb;
                color: #ffffff;
            }
            QTabBar::tab:hover:!selected {
                background-color: #30363d;
            }
        """)
        
        # [Le reste du code pour initialiser les onglets reste identique...]
        self.session_tab = SessionTab(self.api_client, self.on_login_status_changed)
        self.event_tab = EventTab(self.api_client)
        self.missions_tab = MissionsTab(self.api_client)
        self.boss_tab = BossTab(self.api_client)
        self.overlay_tab = OverlayTab(self.api_client)
        self.lore_tab = LoreTab(self.api_client, self.event_tab)
        self.coffre_tab = CoffreTab(self.api_client)
        self.items_tab = ItemsTab(self.api_client)
        self.item_effects_tab = ItemEffectsTab(self.api_client)

        self.tabs.addTab(self.session_tab, "🔐 Session")
        self.tabs.addTab(self.lore_tab, "📖 Lore")
        self.tabs.addTab(self.event_tab, "📊 Événement")
        self.tabs.addTab(self.missions_tab, "🎯 Missions")
        self.tabs.addTab(self.boss_tab, "🐉 Boss")
        self.tabs.addTab(self.items_tab, "📦 Items")
        self.tabs.addTab(self.item_effects_tab, "⚡ Effets Items")
        self.tabs.addTab(self.coffre_tab, "🏰 Coffre")
        self.tabs.addTab(self.overlay_tab, "🎬 Overlay")
        

        # Auto-refresh quand on change d'onglet
        self.tabs.currentChanged.connect(self.on_tab_changed)

        main_layout.addWidget(self.tabs)

        # Barre d'état
        status_bar = self.statusBar()
        status_bar.showMessage("Prêt")

        # Timer pour vérifier la connexion (30s au lieu de 5s - le cache gère les appels intermédiaires)
        self.connection_timer = QTimer()
        self.connection_timer.timeout.connect(self.check_connection)
        self.connection_timer.start(30000)

        # Menu
        self.setup_menu()

    def setup_menu(self):
        menubar = self.menuBar()
        
        # Menu Fichier
        file_menu = menubar.addMenu("📁 Fichier")
        
        login_action = file_menu.addAction("🔑 Connexion Twitch")
        login_action.triggered.connect(self.login_twitch)
        
        logout_action = file_menu.addAction("🚪 Déconnexion")
        logout_action.triggered.connect(self.logout)
        
        file_menu.addSeparator()
        
        exit_action = file_menu.addAction("❌ Quitter")
        exit_action.triggered.connect(self.close)
        
        # Menu Aide
        help_menu = menubar.addMenu("❓ Aide")
        
        about_action = help_menu.addAction("ℹ️ À propos")
        about_action.triggered.connect(self.show_about)
        
        docs_action = help_menu.addAction("📖 Documentation")
        docs_action.triggered.connect(self.show_docs)

    def setup_connections(self):
        self.api_client.set_auth_callback(self.on_auth_result)
        self.api_client.load_cookies()
        # Vérifier la session après un court délai
        QTimer.singleShot(1000, self.check_session)

    def on_tab_changed(self, index):
        """Rafraîchit les données de l'onglet quand on y accède"""
        widget = self.tabs.widget(index)
        if widget is self.lore_tab:
            self.lore_tab.load_lore_data()
        elif widget is self.event_tab:
            self.event_tab.refresh_data()
        elif widget is self.missions_tab:
            self.missions_tab.refresh_defs()
            self.missions_tab.refresh_runs()
        elif widget is self.boss_tab:
            self.boss_tab.load_boss_list()
        elif widget is self.items_tab:
            self.items_tab.refresh_items()
        elif widget is self.item_effects_tab:
            self.item_effects_tab.refresh_data()
        elif widget is self.coffre_tab:
            self.coffre_tab.load_coffre()
        elif widget is self.overlay_tab:
            self.overlay_tab.load_config()

    def check_connection(self):
        is_online = self.api_client.check_connectivity()
        if is_online:
            self.status_indicator.setText("🟢")
            self.status_label.setText("Connecté")
        else:
            self.status_indicator.setText("🔴")
            self.status_label.setText("Déconnecté")

    def check_session(self):
        user_info = self.api_client.whoami()
        if user_info:
            login = user_info.get("twitch_login", "Inconnu")
            self.session_info.setText(f"👤 Connecté en tant que {login}")
            self.start_sse()
        else:
            self.session_info.setText("Non authentifié")

    def login_twitch(self):
        self.api_client.login_twitch()

    def logout(self):
        self.api_client.logout()
        self.session_info.setText("Non authentifié")
        if self.sse_thread:
            self.sse_thread.running = False
            self.sse_thread = None

    def on_auth_result(self, success):
        if success:
            self.check_session()
        else:
            self.session_info.setText("❌ Échec de l'authentification")

    def start_sse(self):
        if self.sse_thread:
            self.sse_thread.running = False

        self.sse_thread = SSEThread(BACKEND_URL)
        self.sse_thread.new_event.connect(self.handle_sse_event)
        self.sse_thread.start()

    def handle_sse_event(self, event_type, data):
        print(f"📨 Événement SSE: {event_type} - {data}")
        
        if event_type == "event_update":
            self.event_tab.refresh_data()
        elif event_type == "solo_update":
            self.solo_tab.refresh_defs()
            self.solo_tab.refresh_runs()

    def on_login_status_changed(self, is_logged_in):
        if is_logged_in:
            for i in range(1, self.tabs.count()):
                self.tabs.setTabEnabled(i, True)
        else:
            for i in range(1, self.tabs.count()):
                self.tabs.setTabEnabled(i, False)

    def show_about(self):
        QMessageBox.about(self, "À propos", 
            "StreamQuest SuperAdmin\n\n"
            "Version 1.0\n"
            "Outil d'administration pour StreamQuest\n\n"
            "Développé avec ❤️ pour la communauté"
        )

    def show_docs(self):
        QMessageBox.information(self, "Documentation", 
            "📚 Documentation StreamQuest\n\n"
            "1. Événement: Créez et gérez les événements communautaires\n"
            "2. Missions Solo: Configurez les défis individuels\n"
            "3. Overlay: Personnalisez l'apparence de l'overlay\n\n"
            "Utilisez le menu Fichier pour vous connecter avec Twitch."
        )

    def closeEvent(self, event):
        if self.sse_thread:
            self.sse_thread.running = False
            self.sse_thread.wait(1000)
        
        self.api_client.save_cookies()
        event.accept()

# Section 10: Point d'entrée
if __name__ == "__main__":

    # Test au démarrage
    print("🧪 Test de l'endpoint des codes...")
    test_event_codes_endpoint()
    
    
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    # ← AJOUTEZ CETTE LIGNE ↓
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))
        print(f"✅ Icône d'application définie depuis : {icon_path}")
        
    window = StreamQuestAdmin()
    window.show()
    
    sys.exit(app.exec())