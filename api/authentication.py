# authentication.py
from rest_framework.authentication import BaseAuthentication
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth import get_user_model
from rest_framework.exceptions import AuthenticationFailed

User = get_user_model()

class CookieJWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        token = request.COOKIES.get('access_token')
        if not token:
            print("Aucun token trouvé dans les cookies.")
            return None
        try:
            access_token = AccessToken(token)
            user = User.objects.get(id=access_token['user_id'])
            print(f"Utilisateur authentifié : {user}")
            return (user, None)
        except Exception as e:
            print(f"Erreur d'authentification : {e}")
            raise AuthenticationFailed("Invalid token")