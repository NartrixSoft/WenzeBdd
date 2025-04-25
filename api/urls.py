from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (CookieTokenRefreshView,RecentConversationsView,
                    ConversationView, SendMessageView,UserCartItemsView,CartItemDetailView,
                    StoreProductListCreateView,CategoryViewSet,
                    TagViewSet,SearchProductView,StoreSearchView,SuggestionCreateView)
from .views import (
    UserViewSet, ProductViewSet, StoreViewSet, MessageViewSet,
    LogoutView,
    SignupView, LoginView,
    ProductListCreateView, ProductDetailView,
    StoreListCreateView, StoreDetailView,
    MessageListCreateView, UserProductsView, StoreProductsView,
    CartListCreateView, CartDeleteView, OrderHistoryView,CartItemCreateView,CurrentUserView,MessageListView,MyStoreView,ConversationCheckView
)

# Router pour les ViewSets
router = DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'products', ProductViewSet)
router.register(r'stores', StoreViewSet)
router.register(r'messages', MessageViewSet, basename='message')
router.register(r'categories', CategoryViewSet)
router.register(r'tags', TagViewSet)

urlpatterns = [
    path('', include(router.urls)),  # Inclut toutes les routes des ViewSets

    # Authentification
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/',LogoutView.as_view(),name='logout'),
    path('me/', CurrentUserView.as_view(), name='current-user'),
    path('refresh/',CookieTokenRefreshView.as_view(),name='token_refresh'),

    # Produits
    path('products/', ProductListCreateView.as_view(), name='product-list-create'),
    path('products/<int:pk>/', ProductDetailView.as_view(), name='product-detail'),
    path('my-product/', UserProductsView.as_view(), name='user-products'),
    path('stores/<int:store_id>/products/', StoreProductListCreateView.as_view(), name='store-products'),

    # Messages
    path("message/recent/", RecentConversationsView.as_view(), name="recent-messages"),
    path('messages/vues/', MessageListCreateView.as_view(), name='message'),
    path('messages/',MessageListView.as_view(),name='conversation'),
    path("check-conversation/",ConversationCheckView.as_view(),name='check-conversation'),
    path("message/conversation/<int:contact_id>/", ConversationView.as_view()),
    path("message/send/", SendMessageView.as_view()),

    # Panier
    path('cart/', CartListCreateView.as_view(), name='cart-list-create'),
    path('cart/<int:pk>/', CartItemDetailView.as_view(), name='cart-item-detail'),
    path('mine/',MyStoreView.as_view(),name='my-stores'),
    # Ajouter un produit au panier
    path('cart-items/', CartItemCreateView.as_view(), name='cart-item-create'),
    path('my-cart/',UserCartItemsView.as_view(),name="my-cart"),
    path("search/products/",SearchProductView.as_view(),name="product-search"),
    path('search/stores/',StoreSearchView.as_view(),name='store-search'),
    path('suggestions/',SuggestionCreateView.as_view(),name='suggestion-create'),

]