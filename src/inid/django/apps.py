from django.apps import AppConfig


class InIDAppConfig(AppConfig):
    name = "inid.django"
    # "django" would be a confusing label
    label = "inid"
    verbose_name = "InID"
