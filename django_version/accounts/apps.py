from django.apps import AppConfig


class AccountsConfig(AppConfig):
    name = "accounts"
    verbose_name = "User Accounts"

    def ready(self):
        """
        Executed when Django loads the app.
        Perform initialization tasks such as registering signals, validators, etc.
        It is called as soon as the registry is fully populated.
        """
        pass
