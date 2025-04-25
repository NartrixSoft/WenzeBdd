from django_filters.rest_framework import DjangoFilterBackend
from django.http import JsonResponse
from django.conf import settings
from django.utils.timezone import now, timedelta
from django.middleware import csrf
from django.db.models import Q,OuterRef,Subquery,Max,Case,When,Value,IntegerField
from rest_framework.response import Response
from django.shortcuts import render
from django.contrib.auth import get_user_model, authenticate
from rest_framework import viewsets, permissions, generics, status
from rest_framework import filters
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken,OutstandingToken
from rest_framework_simplejwt.exceptions import InvalidToken,TokenError
from rest_framework_simplejwt.settings import api_settings
from .serializers import (ProductSerializer, StoreSerializer,
                          MessageSerializer, UserSerializer,
                          CartSerializer, OrderHistorySerializer,
                          SignupSerializer, LoginSerializer,CartItemSerializer,
                          ConversationSerializer,MessageCreateSerializer,CategorySerializer,
                          TagSerializer,SuggestionSerializer)
from .models import Product, Store, Message, Cart, OrderHistory,Conversation,CartItem,Category,Tag,Suggestion
from .authentication import CookieJWTAuthentication
from rest_framework.exceptions import ValidationError
from . import permissions as p
User = get_user_model()
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
import logging

User = get_user_model()
logger = logging.getLogger(__name__)
api_settings.JWT_VERIFY=False


from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
import logging

User = get_user_model()
logger = logging.getLogger(__name__)

class CookieTokenRefreshView(APIView):
    authentication_classes=[]
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        logger.info("Requête de rafraîchissement reçue. Cookies: %s", request.COOKIES)
        
        refresh_token = request.COOKIES.get('refresh_token')
        
        if not refresh_token:
            logger.error("Aucun refresh_token dans les cookies")
            return Response({"error": "Refresh token manquant"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # DEBUG: Décodage sans vérification
            from jwt import decode
            decoded_debug = decode(refresh_token, options={"verify_signature": False})
            logger.debug("Décodage debug: %s", decoded_debug)
            
            # Validation réelle
            refresh = RefreshToken(refresh_token)
            logger.info("Refresh token validé pour l'utilisateur %s", refresh['user_id'])
            
            # Blacklist l'ancien token
            refresh.blacklist()
            
            # Génération nouveaux tokens
            user = User.objects.get(id=refresh['user_id'])
            new_refresh = RefreshToken.for_user(user)
            new_access = str(new_refresh.access_token)
            
            response = Response({
                "access": new_access,
                "refresh": str(new_refresh)
            })

            # Configuration des cookies
            cookie_params = {
                'httponly': True,
                'secure': False,
                'samesite': 'Lax',
                'max_age': 7 * 24 * 60 * 60,
            }
            response.set_cookie('access_token', new_access, 
            path='/',
            **cookie_params)
            response.set_cookie('refresh_token', str(new_refresh),
            path="/api/",
            **cookie_params)
            
            logger.info("Nouveaux tokens générés avec succès")
            return response

        except InvalidToken as e:
            logger.error("Token invalide: %s", str(e))
            return Response({"error": "Token invalide"}, status=status.HTTP_403_FORBIDDEN)
        except User.DoesNotExist:
            logger.error("Utilisateur non trouvé")
            return Response({"error": "Utilisateur introuvable"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.exception("Erreur inattendue")
            return Response({"error": "Erreur serveur"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

class CurrentUserView(APIView):
    authentication_classes = [CookieJWTAuthentication]
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        print("User : ", request.user)
        print("Is authenticated ? ", request.user.is_authenticated)
        print("Cookie Recu : ",request.COOKIES)
        if not request.user or not request.user.is_authenticated:
            return Response({'detail': 'Utilisateur non authentifié.'}, status=401)

        serializer = UserSerializer(request.user, context={'request': request})
        return Response(serializer.data)

    def patch(self, request):
        print('FILES:', request.FILES)
        print('DATA:', request.data)
        serializer = UserSerializer(request.user, data=request.data, partial=True, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request):
        serializer = UserSerializer(request.user, data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SignupView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = SignupSerializer
    permission_classes = [permissions.AllowAny]

class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            response = Response({
                "access": access_token,
                "refresh": str(refresh),
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                }
            })

            cookie_params = {
                'httponly': True,
                'secure': False,  # True en production
                'samesite': 'Lax',
                'max_age': 7 * 24 * 60 * 60,
            }

            response.set_cookie(
                'refresh_token',
                str(refresh),
                path='/api/',  # Changé pour être plus permissif
                **cookie_params
            )
            
            response.set_cookie(
                'access_token',
                access_token,
                path='/',
                **cookie_params
            )
            print("refresh :",refresh)
            print("Cookies définis avec succès")
            return response
            
        return Response({"detail": "Identifiants invalides"}, status=status.HTTP_401_UNAUTHORIZED)


class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        if not refresh_token:
            return Response({'error': 'Pas de token trouvé'}, status=400)
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except Exception as e:
            return Response({'error': 'Token invalide'}, status=400)

        response = Response({'message': 'Déconnexion réussie'}, status=200)
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        return response


# Gestion des produits
class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    
    # Pour filtres simples
    filterset_fields = ['store', 'category', 'available']
    
    # Pour recherche fulltext
    search_fields = ['name', 'description']

    # Pour trier
    ordering_fields = ['price', 'created_at']

    def perform_create(self, serializer):
        store_id = self.request.data.get("store")
        user = self.request.user
        if store_id:
            try:
                store = Store.objects.get(id=store_id, owner=user)
                serializer.save(owner=user, store=store)
            except Store.DoesNotExist:
                raise ValidationError({"store": "Ce magasin n'existe pas ou ne vous appartient pas."})
        else:
            serializer.save(owner=user)


from rest_framework import filters

class ProductListCreateView(generics.ListCreateAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    filter_backends = [filters.OrderingFilter]
    ordering_fields = ['price', 'created_at', 'category__name']  # tu ajoutes ici tous les champs triables
    ordering = ['-created_at']  # par défaut on trie du plus récent


class ProductDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

class CategoryViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [permissions.AllowAny]
    queryset = Category.objects.all().order_by('name')
    serializer_class = CategorySerializer

class TagViewSet(viewsets.ModelViewSet):
    queryset = Tag.objects.all()
    serializer_class = TagSerializer

class SearchProductView(APIView):
    permission_classes=[permissions.AllowAny]

    def get(self,request):
        query=request.GET.get("query","")
        if query:
            products=Product.objects.filter(name__icontains=query)
            print(f"requete : {query}")
            serializer=ProductSerializer(products,many=True,context={'request':request})
            print(serializer.data)

            return Response(serializer.data)
            return Response([])

# Gestion des magasins
class MyStoreView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        stores = Store.objects.filter(owner=request.user)
        serializer = StoreSerializer(stores, many=True)
        return Response(serializer.data)

class StoreViewSet(viewsets.ModelViewSet):
    serializer_class = StoreSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly, p.IsOwnerOrReadOnly]
    queryset=Store.objects.all()
    def get_queryset(self):
        # Tu peux retourner tous les stores si c’est public,
        # ou filtrer par user si tu veux une vue "Mes Stores"
        return Store.objects.all()

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

class StoreListCreateView(generics.ListCreateAPIView):
    queryset = Store.objects.all()
    serializer_class = StoreSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

class StoreDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Store.objects.all()
    serializer_class = StoreSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

class StoreProductsView(generics.ListAPIView):
    serializer_class = ProductSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    
    def get_queryset(self):
        store_id = self.kwargs['store_id']
        return Product.objects.filter(store_id=store_id)

class StoreProductListCreateView(generics.ListCreateAPIView):
    serializer_class = ProductSerializer

    def get_queryset(self):
        store_id = self.kwargs["store_id"]
        return Product.objects.filter(store_id=store_id)

    def perform_create(self, serializer):
        store = Store.objects.get(id=self.kwargs["store_id"])
        if store.owner != self.request.user:
            raise PermissionDenied("Vous n'êtes pas le propriétaire de ce magasin.")
        serializer.save(store=store)


class StoreSearchView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        query = request.GET.get("q", "")
        if query:
            stores = Store.objects.filter(
                Q(name__icontains=query) | Q(description__icontains=query)
            )
        else:
            stores = Store.objects.none()
        serializer = StoreSerializer(stores, many=True)
        return Response(serializer.data)


class UserProductsView(generics.ListAPIView):
    serializer_class = ProductSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    
    def get_queryset(self):
        user_id = self.request.user.id
        return Product.objects.filter(owner_id=user_id)

# Gestion des messages
class ConversationView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer=MessageSerializer
    def get(self, request, contact_id):
        user = request.user
        try:
            contact = User.objects.get(id=contact_id)
        except User.DoesNotExist:
            return Response({"error": "Utilisateur introuvable"}, status=404)

        messages = Message.objects.filter(
            (Q(sender=user) & Q(receiver=contact)) |
            (Q(sender=contact) & Q(receiver=user))
        ).order_by("created_at")

        
        return Response(MessageSerializer(messages, many=True, context={'request': request}).data)


class SendMessageView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        receiver_id = request.data.get('receiver_id')
        content = request.data.get('content')

        if not receiver_id or not content:
            return Response({"error": "Tous les champs sont requis"}, status=400)

        try:
            receiver = User.objects.get(id=receiver_id)
        except User.DoesNotExist:
            return Response({"error": "Destinataire introuvable"}, status=404)

        message = Message.objects.create(
            sender=request.user,
            receiver=receiver,
            content=content
        )
        serializer = MessageSerializer(message, context={'request': request})
        return Response(serializer.data, status=status.HTTP_201_CREATED)



class RecentConversationsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user

        # Récupère tous les messages où le user est impliqué, triés du plus récent au plus ancien
        messages = Message.objects.filter(
            Q(sender=user) | Q(receiver=user)
        ).order_by('-created_at')

        # Garder le dernier message pour chaque contact unique
        seen_contacts = set()
        recent_messages = []

        for message in messages:
            # Identifier le contact (l'autre personne dans la conversation)
            contact = message.receiver if message.sender == user else message.sender

            if contact.id not in seen_contacts:
                seen_contacts.add(contact.id)
                recent_messages.append(message)

        serializer = MessageSerializer(recent_messages, many=True, context={'request': request})
        return Response(serializer.data)


class MessageViewSet(viewsets.ModelViewSet):
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return Message.objects.filter(Q(sender=user) | Q(receiver=user)).distinct()

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return MessageCreateSerializer
        return MessageSerializer

    def perform_create(self, serializer):
        sender = self.request.user
        receiver_id = self.request.data.get('receiver')
        receiver = User.objects.filter(id=receiver_id).first()

        if not receiver:
            raise serializers.ValidationError({"receiver": "Utilisateur introuvable."})

        # Vérifie s’il y a déjà une conversation
        conversation = Conversation.objects.filter(participants=sender)\
                                           .filter(participants=receiver).first()

        if not conversation:
            conversation = Conversation.objects.create()
            conversation.participants.add(sender, receiver)

        serializer.save(
            sender=sender,
            receiver=receiver,
            conversation=conversation
        )

class MessageListCreateView(generics.ListCreateAPIView):
    serializer_class = MessageSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        return Message.objects.filter(Q(sender=user) | Q(receiver=user)).distinct()

class MessageListView(generics.ListAPIView):
    serializer_class = MessageSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        receiver_id = self.request.query_params.get('receiver_id')

        if not receiver_id:
            raise ValidationError("Le parametre 'receiver_id' est requis.")  # Pas de receiver, on retourne rien

        return Message.objects.filter(
            Q(sender=user, receiver_id=receiver_id) |
            Q(sender_id=receiver_id, receiver=user)
        ).order_by('created_at')
    
    def list(self, request, *args, **kwargs):
        # Ajout d'une gestion de la réponse pour s'assurer qu'un tableau est renvoyé
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        print(queryset)
        return Response(serializer.data)

class ConversationCheckView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user
        receiver_id = request.query_params.get('receiver_id')

        if not receiver_id:
            return Response({"error": "receiver_id est requis"}, status=400)

        receiver = User.objects.filter(id=receiver_id).first()
        if not receiver:
            return Response({"error": "Utilisateur introuvable"}, status=404)

        conversation = Conversation.objects.filter(participants=user).filter(participants=receiver).first()
        if conversation:
            return Response({"conversation_id": conversation.id})
        else:
            return Response({"conversation_id": None})
class ConversationListView(generics.ListAPIView):
    serializer_class = ConversationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Conversation.objects.filter(participants=self.request.user)

# Gestion du panier
class CartListCreateView(generics.ListCreateAPIView):
    serializer_class = CartSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return Cart.objects.filter(user=self.request.user)

class CartDeleteView(generics.DestroyAPIView):
    serializer_class = CartSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Cart.objects.filter(user=self.request.user)

class CartItemCreateView(generics.CreateAPIView):
    serializer_class = CartItemSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        cart = Cart.objects.filter(user=self.request.user).first()  # ✅ Prend le premier panier existant
        if not cart:
            cart = Cart.objects.create(user=self.request.user)  # ✅ Crée un panier si aucun n'existe
        serializer.save(cart=cart)  # ✅ Associe l'élément au panier trouvé ou créé

class CartItemDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = CartItemSerializer
    permission_classes = [permissions.IsAuthenticated]
    queryset = CartItem.objects.all()

    def get_queryset(self):
        # Assure-toi que l'utilisateur a bien accès uniquement à ses propres items
        return CartItem.objects.filter(cart__user=self.request.user)


class UserCartItemsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            cart = Cart.objects.get(user=request.user)
            items = cart.items.all()
            serializer = CartItemSerializer(items, many=True)
            return Response(serializer.data)
        except Cart.DoesNotExist:
            return Response([], status=200)

# Historique des commandes
class OrderHistoryView(generics.ListAPIView):
    serializer_class = OrderHistorySerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return OrderHistory.objects.filter(user=self.request.user).order_by('-date')

class CategoryViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Category.objects.all().order_by('name')
    serializer_class = CategorySerializer
    permission_classes = [permissions.AllowAny]


class SuggestionCreateView(generics.CreateAPIView):
    queryset=Suggestion.objects.all()
    serializer_class=SuggestionSerializer
    permission_classes=[permissions.AllowAny]

    def perform_create(self,serializer):
        serializer.save(user=self.request.user if self.request.user.is_authenticated else None)