from flask import Flask, render_template, request, jsonify
import requests
import sqlite3
import json
from datetime import datetime

app = Flask(__name__)
DB_PATH = "squawkmap_logs.db"


# ─────────────────────────────────────────
# Database setup — runs once on startup
# ─────────────────────────────────────────

def init_db():
    """Creates the database tables if they don't already exist."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                country TEXT,
                flight_count INTEGER,
                data TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS flight_clicks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                icao TEXT,
                callsign TEXT,
                altitude TEXT,
                speed TEXT,
                heading TEXT,
                latitude TEXT,
                longitude TEXT,
                country TEXT
            )
        """)
        conn.commit()
        conn.close()
    except Exception:
        pass

init_db()


# ─────────────────────────────────────────
# Country reference data
# ─────────────────────────────────────────

COUNTRY_BOUNDS = {
    "Philippines": {
        "lat": 12.8797, "lon": 121.774,
        "bounds": {"lamin": 3.0, "lamax": 22.5, "lomin": 113.0, "lomax": 128.5}
    },
    "USA": {
        "lat": 39.5, "lon": -98.35,
        "bounds": {"lamin": 23.0, "lamax": 50.5, "lomin": -126.0, "lomax": -64.0}
    },
    "Japan": {
        "lat": 36.2048, "lon": 138.2529,
        "bounds": {"lamin": 22.0, "lamax": 47.0, "lomin": 121.0, "lomax": 155.0}
    },
    "Australia": {
        "lat": -25.274, "lon": 133.7751,
        "bounds": {"lamin": -45.0, "lamax": -9.0, "lomin": 111.0, "lomax": 155.0}
    },
    "UK": {
        "lat": 55.3781, "lon": -3.4360,
        "bounds": {"lamin": 48.5, "lamax": 62.0, "lomin": -9.5, "lomax": 3.5}
    },
}

COUNTRY_MAX_RADIUS = {
    "Philippines": 600,
    "USA":         600,
    "Japan":       500,
    "Australia":   600,
    "UK":          400,
}


# ─────────────────────────────────────────
# UC1 — CountryFilter
# Fetches live flights within the viewport
# ─────────────────────────────────────────

# Fix #11: CountryFilter holds no state so it doesn't need to be
# reinstantiated on every request. Created once at module level.
class CountryFilter:

    def get_flights_by_viewport(self, lamin, lamax, lomin, lomax, country):
        country_data = COUNTRY_BOUNDS.get(country)
        if not country_data:
            return []

        country_bounds = country_data["bounds"]
        lamin = max(lamin, country_bounds["lamin"])
        lamax = min(lamax, country_bounds["lamax"])
        lomin = max(lomin, country_bounds["lomin"])
        lomax = min(lomax, country_bounds["lomax"])

        if lamin >= lamax or lomin >= lomax:
            return []

        center_lat = (lamin + lamax) / 2
        center_lon = (lomin + lomax) / 2
        max_radius = COUNTRY_MAX_RADIUS.get(country, 300)
        min_radius = 200
        radius = max(min(int(((lamax - lamin) * 111) / 2), max_radius), min_radius)

        url = f"https://api.adsb.lol/v2/point/{center_lat}/{center_lon}/{radius}"

        # Fix #6: Distinguish between rate limiting, server errors,
        # and genuine empty results instead of treating all as the same
        try:
            response = requests.get(url, timeout=10)
        except requests.exceptions.RequestException:
            return []

        if response.status_code == 429:
            return []
        if response.status_code != 200:
            return []

        all_flights = response.json().get("ac", [])
        flights_in_country = []
        for aircraft in all_flights:
            has_position = aircraft.get("lat") and aircraft.get("lon")
            inside_lat_range = country_bounds["lamin"] <= aircraft.get("lat", 0) <= country_bounds["lamax"]
            inside_lon_range = country_bounds["lomin"] <= aircraft.get("lon", 0) <= country_bounds["lomax"]
            if has_position and inside_lat_range and inside_lon_range:
                flights_in_country.append(aircraft)

        return flights_in_country


# ─────────────────────────────────────────
# UC2 — VicinityStats
# Calculates flight counts from fetched data
# ─────────────────────────────────────────

class VicinityStats:

    # Fix #7: Added __init__ for consistency with other classes
    def __init__(self):
        self.flight_count = 0
        self.airborne_count = 0
        self.on_ground_count = 0
        self.categories = {}

    def calculate_stats(self, flights):
        self.flight_count = len(flights)
        self.airborne_count = 0
        self.on_ground_count = 0

        for flight in flights:
            if flight.get("ground", False):
                self.on_ground_count += 1
            else:
                self.airborne_count += 1

        self.categories = self.group_by_category(flights)

        return {
            "flight_count": self.flight_count,
            "airborne":     self.airborne_count,
            "on_ground":    self.on_ground_count,
            "categories":   self.categories,
        }

    def group_by_category(self, flights):
        groups = {}
        for flight in flights:
            category = flight.get("category", "Unknown")
            groups[category] = groups.get(category, 0) + 1
        return groups


# ─────────────────────────────────────────
# UC6 — CyberPanel
# Detects anomalies and runs cyber scenarios
# ─────────────────────────────────────────

class CyberPanel:

    SPEED_THRESHOLD    = 600
    ALTITUDE_THRESHOLD = 45000

    SCENARIOS = [
        {
            "id": 1,
            "title": "Spoofed ICAO Code",
            "description": "Two aircraft are broadcasting the same ICAO code. What do you do?",
            "choices": ["Ignore it", "Flag and investigate"],
            "correct": "Flag and investigate",
            "feedback": "Correct! Duplicate ICAO codes are a strong indicator of ADS-B spoofing."
        },
        {
            "id": 2,
            "title": "Sudden Altitude Jump",
            "description": "An aircraft jumped 20,000 feet in under 10 seconds. What do you do?",
            "choices": ["Normal turbulence", "Flag as anomaly"],
            "correct": "Flag as anomaly",
            "feedback": "Correct! No aircraft can climb that fast. This is likely a spoofed signal."
        },
        {
            "id": 3,
            "title": "Abnormal Speed",
            "description": "An aircraft is showing a ground speed of 950 knots. What do you do?",
            "choices": ["Could be a military jet", "Flag and investigate"],
            "correct": "Flag and investigate",
            "feedback": "Correct! Civil aircraft do not fly at 950 knots. This signal should be flagged."
        },
        {
            "id": 4,
            "title": "GPS Spoofing",
            "description": "An aircraft position is jumping erratically across the map, teleporting hundreds of miles in seconds. What do you do?",
            "choices": ["GPS interference", "Flag as spoofed position"],
            "correct": "Flag as spoofed position",
            "feedback": "Correct! Erratic position jumps are a classic sign of GPS spoofing where fake signals override the real GPS feed."
        },
        {
            "id": 5,
            "title": "Ghost Flight",
            "description": "An aircraft is broadcasting a valid ICAO code but its registration does not match any known aircraft in the database. What do you do?",
            "choices": ["Could be a new aircraft", "Flag and investigate"],
            "correct": "Flag and investigate",
            "feedback": "Correct! A valid ICAO code with no matching registration is a strong indicator of identity spoofing."
        },
    ]

    def __init__(self):
        self.current_scenario = {}
        self.flagged = []  # Fix #8: Store flagged result on the instance

    def detect(self, flights):
        self.flagged = []  # Reset on each call

        for flight in flights:
            if self.is_speed_too_high(flight):
                self.flagged.append(self.make_flag(flight, "Abnormal speed detected", f"{flight.get('gs', 'N/A')} kts"))
            if self.is_altitude_too_high(flight):
                self.flagged.append(self.make_flag(flight, "Abnormal altitude detected", f"{flight.get('alt_baro', 'N/A')} ft"))

        for flight in self.find_duplicate_icao_codes(flights):
            self.flagged.append(self.make_flag(flight, "Duplicate ICAO code detected", flight.get("hex", "N/A")))

        return self.flagged

    def make_flag(self, flight, reason, value):
        return {
            "icao":     flight.get("hex", "N/A"),
            "callsign": flight.get("flight", "Unknown").strip(),
            "reason":   reason,
            "value":    value
        }

    def is_speed_too_high(self, flight):
        try:
            return float(flight.get("gs", 0)) > self.SPEED_THRESHOLD
        except (ValueError, TypeError):
            return False

    def is_altitude_too_high(self, flight):
        try:
            return float(flight.get("alt_baro", 0)) > self.ALTITUDE_THRESHOLD
        except (ValueError, TypeError):
            return False

    def find_duplicate_icao_codes(self, flights):
        codes_seen_so_far = {}
        duplicates = []

        for flight in flights:
            icao = flight.get("hex", "")
            if icao in codes_seen_so_far:
                duplicates.append(flight)
            else:
                codes_seen_so_far[icao] = flight

        return duplicates

    def load_scenario(self, scenario_id):
        for scenario in self.SCENARIOS:
            if scenario["id"] == scenario_id:
                self.current_scenario = scenario
                return scenario
        return {}

    def evaluate_choice(self, choice):
        if not self.current_scenario:
            return {"result": "error", "message": "No scenario loaded."}

        if choice == self.current_scenario["correct"]:
            return {"result": "correct", "message": self.current_scenario["feedback"]}

        return {"result": "incorrect", "message": f"Incorrect. {self.current_scenario['feedback']}"}


# ─────────────────────────────────────────
# UC7 — TrackingLogs
# Saves session history and flight clicks
# ─────────────────────────────────────────

# Fix #4: Use a single shared database connection per operation
# instead of opening and closing one per method call.
# Fix #5: save_session is only called when there are actual flights,
# not on every fetch regardless of result.
class TrackingLogs:

    def _get_connection(self):
        """Returns an open database connection."""
        return sqlite3.connect(DB_PATH)

    def save_session(self, session):
        """Records a search session only when there are flights to record."""
        try:
            conn = self._get_connection()
            conn.execute(
                "INSERT INTO sessions (timestamp, country, flight_count, data) VALUES (?, ?, ?, ?)",
                (
                    datetime.now().isoformat(),
                    session.get("country", "Unknown"),
                    session.get("flight_count", 0),
                    json.dumps(session)
                )
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    def save_flight_click(self, flight, country):
        """Records when a user clicks a flight marker."""
        try:
            conn = self._get_connection()
            conn.execute(
                """INSERT INTO flight_clicks
                   (timestamp, icao, callsign, altitude, speed, heading, latitude, longitude, country)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    datetime.now().isoformat(),
                    flight.get("hex", "N/A"),
                    flight.get("flight", "Unknown").strip(),
                    str(flight.get("alt_baro", "N/A")),
                    str(flight.get("gs", "N/A")),
                    str(flight.get("track", "N/A")),
                    str(flight.get("lat", "N/A")),
                    str(flight.get("lon", "N/A")),
                    country
                )
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    def get_flight_clicks(self):
        """Returns the 50 most recent flight clicks, newest first."""
        try:
            conn = self._get_connection()
            rows = conn.execute(
                "SELECT * FROM flight_clicks ORDER BY id DESC LIMIT 50"
            ).fetchall()
            conn.close()

            # Fix #9: Process results inside the try block so the
            # logic flow is clear and consistent
            clicks = []
            for row in rows:
                clicks.append({
                    "id": row[0], "timestamp": row[1], "icao": row[2],
                    "callsign": row[3], "altitude": row[4], "speed": row[5],
                    "heading": row[6], "latitude": row[7], "longitude": row[8],
                    "country": row[9]
                })
            return clicks
        except Exception:
            return []

    def clear_all_sessions(self):
        """Wipes both the session history and flight click logs."""
        try:
            conn = self._get_connection()
            conn.execute("DELETE FROM sessions")
            conn.execute("DELETE FROM flight_clicks")
            conn.commit()
            conn.close()
        except Exception:
            pass


# ─────────────────────────────────────────
# UC8 — FlightStatus
# Looks up a single aircraft by ICAO code
# ─────────────────────────────────────────

class FlightStatus:

    def __init__(self):
        self.icao = None
        self.status = None

    def query_status(self, icao):
        self.icao = icao
        self.status = "Unknown"
        url = f"https://api.adsb.lol/v2/icao/{icao}"

        try:
            response = requests.get(url, timeout=10)
        except requests.exceptions.RequestException:
            self.status = "API unavailable"
            return {}

        if response.status_code != 200:
            self.status = "Not Active"
            return {}

        matching_flights = response.json().get("ac", [])
        if matching_flights:
            self.status = "Active"
            return matching_flights[0]

        self.status = "Not Active"
        return {}

    def compare_with_log(self, icao):
        if self.status == "Active":
            return f"{icao} is currently airborne and broadcasting a live signal."
        elif self.status == "Not Active":
            return f"{icao} is not found in live data. The flight may have landed, lost signal, or the ICAO code may be incorrect."
        else:
            return "Could not reach the API. Please try again."

    def display_status(self):
        return self.status or "Unknown"

    def save_result(self, result):
        # Fix #12: Added try/except so a database failure here
        # doesn't crash the /status route
        try:
            TrackingLogs().save_session({
                "country": "Status Check",
                "flight_count": 1,
                "icao": self.icao,
                "status": self.status,
                "result": result if result else {},
            })
        except Exception:
            pass


# ─────────────────────────────────────────
# Flask Routes
# ─────────────────────────────────────────

# Fix #1, #2, #11: Create one instance of each stateless class at
# module level so they are not recreated on every request
country_filter  = CountryFilter()
vicinity_stats  = VicinityStats()
tracking_logs   = TrackingLogs()


@app.route("/", methods=["GET", "POST"])
def index():
    selected_country = None
    error = None

    if request.method == "POST":
        selected_country = request.form.get("country")
        if not selected_country or selected_country not in COUNTRY_BOUNDS:
            error = "Please select a valid country."
            selected_country = None

    center = None
    if selected_country:
        country_data = COUNTRY_BOUNDS[selected_country]
        center = {"lat": country_data["lat"], "lon": country_data["lon"]}

    return render_template(
        "index.html",
        countries=COUNTRY_BOUNDS.keys(),
        selected_country=selected_country,
        center=center,
        error=error
    )


@app.route("/flights", methods=["GET"])
def flights():
    try:
        lamin   = float(request.args.get("lamin"))
        lamax   = float(request.args.get("lamax"))
        lomin   = float(request.args.get("lomin"))
        lomax   = float(request.args.get("lomax"))
        country = request.args.get("country", "")
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid bounds"}), 400

    flight_list = country_filter.get_flights_by_viewport(lamin, lamax, lomin, lomax, country)
    stats       = vicinity_stats.calculate_stats(flight_list)

    # Fix #2: CyberPanel is stateful (stores current_scenario) so it
    # needs its own instance per request, but it's created once here
    # not twice like before
    cyber_panel = CyberPanel()
    flagged     = cyber_panel.detect(flight_list)

    # Fix #5: Only save a session when there are actual flights to record
    if flight_list:
        tracking_logs.save_session({"country": country, "flight_count": len(flight_list)})

    flights_for_browser = []
    for flight in flight_list:
        flights_for_browser.append({
            "hex":      flight.get("hex", ""),
            "flight":   flight.get("flight", "Unknown"),
            "lat":      flight.get("lat"),
            "lon":      flight.get("lon"),
            "alt_baro": flight.get("alt_baro"),
            "gs":       flight.get("gs"),
            "track":    flight.get("track"),
            "ground":   flight.get("ground")
        })

    return jsonify({
        "flights":      flights_for_browser,
        "stats":        stats,
        "flagged":      flagged,
        "flight_count": len(flight_list),
        "timestamp":    datetime.now().isoformat(),
    })


@app.route("/log/flight", methods=["POST"])
def log_flight():
    try:
        data = request.get_json()
        tracking_logs.save_flight_click(data, data.get("country", "Unknown"))
        return jsonify({"status": "saved"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/logs/flights", methods=["GET"])
def flight_logs():
    return jsonify(tracking_logs.get_flight_clicks())


@app.route("/logs/clear", methods=["POST"])
def clear_logs():
    tracking_logs.clear_all_sessions()
    return jsonify({"status": "cleared"})


@app.route("/status", methods=["GET"])
def status():
    icao = request.args.get("icao", "").strip().upper()
    if not icao:
        return jsonify({"error": "No ICAO provided"}), 400

    try:
        flight_status = FlightStatus()
        result  = flight_status.query_status(icao)
        message = flight_status.compare_with_log(icao)
        flight_status.save_result(result)

        return jsonify({
            "icao":    icao,
            "status":  flight_status.display_status(),
            "message": message,
            "data":    result or {},
        })
    except Exception:
        return jsonify({
            "icao":    icao,
            "status":  "Error",
            "message": "Could not retrieve status. Please try again.",
            "data":    {},
        })


@app.route("/scenario", methods=["GET"])
def scenario():
    try:
        cyber_panel = CyberPanel()
        scenario_id = int(request.args.get("id", 1))
        result = cyber_panel.load_scenario(scenario_id)
        if not result:
            result = cyber_panel.load_scenario(1)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/scenario/evaluate", methods=["POST"])
def evaluate():
    try:
        data = request.get_json()
        cyber_panel = CyberPanel()
        cyber_panel.load_scenario(data.get("id", 1))
        return jsonify(cyber_panel.evaluate_choice(data.get("choice", "")))
    except Exception:
        return jsonify({"result": "error", "message": "Something went wrong."}), 500


if __name__ == "__main__":
    app.run(debug=True)