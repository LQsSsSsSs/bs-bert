import os


def _load_dotenv() -> None:
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    path = os.path.join(root, ".env")
    if not os.path.exists(path):
        return

    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except Exception:
        return


_load_dotenv()


class Settings:
    def __init__(self) -> None:
        self.app_title = os.getenv("APP_TITLE", "CVSS-BERT API")
        self.app_version = os.getenv("APP_VERSION", "1.0.0")
        self.database_url = os.getenv(
            "DATABASE_URL",
            "mysql+pymysql://root:password@localhost:3306/cvss_bert?charset=utf8mb4",
        )
        self.auto_create_tables = os.getenv("AUTO_CREATE_TABLES", "0") == "1"
        self.enabled_plugins = [
            p.strip()
            for p in os.getenv("ENABLED_PLUGINS", "").split(",")
            if p.strip()
        ]
        self.cors_origins = [
            o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",") if o.strip()
        ]


settings = Settings()

