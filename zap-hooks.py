import json
import urllib.request

def zap_started(zap, target):
    context_name = "Spring Boot API"
    context_id = zap.context.new_context(context_name)
    zap.context.include_in_context(context_name, target + ".*")

    # 1. Definiranje rute za login (prema tvom @RequestMapping("/auth"))
    login_url = target + "/auth/login"

    # 2. Dohvaćanje tokena za ADMINA (admin / admin123)
    admin_token = get_jwt_token(login_url, "admin", "admin123")

    # 3. Dohvaćanje tokena za običnog USERA (marko / marko123)
    user_token = get_jwt_token(login_url, "marko", "marko123")

    # 4. Kreiranje korisnika unutar ZAP-a kako bi on znao da postoje dvije sesije
    admin_user_id = zap.users.new_user(context_id, "AdminUser")
    zap.users.set_user_enabled(context_id, admin_user_id, "true")

    regular_user_id = zap.users.new_user(context_id, "RegularUser")
    zap.users.set_user_enabled(context_id, regular_user_id, "true")

    # Spremanje tokena u globalnu skriptu kako bi ih "sending_request" funkcija mogla čitati
    global tokens
    tokens = {
        "AdminUser": admin_token,
        "RegularUser": user_token
    }
    print("ZAP Korisnici uspješno konfigurirani s važećim JWT tokenima!")

def get_jwt_token(url, username, password):
    """Pomoćna funkcija koja šalje stvarni HTTP POST zahtjev na tvoj API i vraća token"""
    try:
        data = json.dumps({"username": username, "password": password}).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req) as response:
            # Budući da tvoj kontroler vraća čisti String (token), samo ga pročitamo
            return response.read().decode('utf-8')
    except Exception as e:
        print(f"Greška prilikom dohvaćanja tokena za {username}: {e}")
        return None

def sending_request(zap, id, msg):
    global tokens
    token = tokens.get("AdminUser")
    if token:
        msg.getRequestHeader().setHeader(
            "Authorization", f"Bearer {token}"
        )
    return msg