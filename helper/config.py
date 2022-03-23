from pydantic import BaseSettings


class Settings(BaseSettings):
    app_name: str = None
    app_version: str = None
    app_key: str = 'fdgfd465454'
    stripe_secret_key: str = None
    stripe_pub_key: str = None

    class Config:
        env_file = '.env'
