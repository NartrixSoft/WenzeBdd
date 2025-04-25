from django.contrib import admin
from .models import User, Category, Tag, Product, Store, Message, Conversation, Cart, CartItem, OrderHistory, Suggestion

class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'phone', 'is_active', 'is_staff')
    list_filter = ('is_active', 'is_staff')
    search_fields = ('username', 'email', 'phone')
    ordering = ('username',)
    
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'description')
    search_fields = ('name',)
    ordering = ('name',)

class TagAdmin(admin.ModelAdmin):
    list_display = ('name',)
    search_fields = ('name',)
    ordering = ('name',)

class ProductAdmin(admin.ModelAdmin):
    list_display = ('name', 'price', 'currency', 'available', 'store', 'owner', 'category', 'created_at')
    list_filter = ('available', 'currency', 'category')
    search_fields = ('name', 'description', 'owner__username', 'store__name')
    ordering = ('-created_at',)

class StoreAdmin(admin.ModelAdmin):
    list_display = ('name', 'owner', 'is_public', 'created_at', 'updated_at')
    list_filter = ('is_public',)
    search_fields = ('name', 'owner__username')
    ordering = ('-created_at',)

class MessageAdmin(admin.ModelAdmin):
    list_display = ('sender', 'receiver', 'content', 'created_at')
    list_filter = ('created_at', 'sender', 'receiver')
    search_fields = ('sender__username', 'receiver__username', 'content')
    ordering = ('-created_at',)

class ConversationAdmin(admin.ModelAdmin):
    list_display = ('id', 'created_at', 'get_participants')
    search_fields = ('id',)
    ordering = ('-created_at',)
    
    def get_participants(self, obj):
        return ", ".join([user.username for user in obj.participants.all()])
    get_participants.short_description = 'Participants'

class CartAdmin(admin.ModelAdmin):
    list_display = ('user',)
    search_fields = ('user__username',)
    ordering = ('user__username',)

class CartItemAdmin(admin.ModelAdmin):
    list_display = ('cart', 'product', 'quantity')
    list_filter = ('cart',)
    search_fields = ('product__name', 'cart__user__username')
    ordering = ('cart',)

class OrderHistoryAdmin(admin.ModelAdmin):
    list_display = ('user', 'product_name', 'price', 'store_name', 'bought_at')
    list_filter = ('bought_at',)
    search_fields = ('user__username', 'product_name', 'store_name')
    ordering = ('-bought_at',)

class SuggestionAdmin(admin.ModelAdmin):
    list_display = ('user','name', 'email', 'phone', 'created_at', 'message')
    list_filter = ('created_at',)
    search_fields = ('user','name', 'email', 'phone', 'message')
    ordering = ('-created_at',)

# Enregistrer les modèles dans l'admin
admin.site.register(User, UserAdmin)
admin.site.register(Category, CategoryAdmin)
admin.site.register(Tag, TagAdmin)
admin.site.register(Product, ProductAdmin)
admin.site.register(Store, StoreAdmin)
admin.site.register(Message, MessageAdmin)
admin.site.register(Conversation, ConversationAdmin)
admin.site.register(Cart, CartAdmin)
admin.site.register(CartItem, CartItemAdmin)
admin.site.register(OrderHistory, OrderHistoryAdmin)
admin.site.register(Suggestion, SuggestionAdmin)