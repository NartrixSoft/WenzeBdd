
from django.contrib.auth.hashers import make_password
from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Product,Store,Message,CartItem,OrderHistory,Cart,Conversation,Category,Tag,Suggestion


User=get_user_model()
class UserSerializer(serializers.ModelSerializer):
    profile_picture_url = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name', 'email', 'phone', 'address', 'profile_picture', 'profile_picture_url', 'bios','date_joined']

    def get_profile_picture_url(self, obj):
        request = self.context.get('request')
        if request and obj.profile_picture and hasattr(obj.profile_picture, 'url'):
            return request.build_absolute_uri(obj.profile_picture.url)
        return None


class SignupSerializer(serializers.ModelSerializer):
    password=serializers.CharField(write_only=True)
    class Meta:
        model=User
        fields=['username','email','password',
                'phone','address','profile_picture','bios']
    def create(self, validated_data):
        validated_data['password']=make_password(validated_data['password'])
        return User.objects.create(**validated_data)
    
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=100)
    password = serializers.CharField(write_only=True)
    class Meta:
        model = User
        fields = ['username', 'password']

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')
        print(f"a partir du serialiseur : l'utilisateur {username} avec le mot de passe {password}")
        user = User.objects.filter(username=username).first()

        if user and user.check_password(password):
            return data  # Retourne les données validées
        raise serializers.ValidationError("Invalid username or password")

class UserRegisterSerializer(serializers.ModelSerializer):
    password=serializers.CharField(write_only=True)
    class Meta:
        model=User
        fields=['username','email','password','first_name','last_name']
        
        def create(self,validated_data):
            user=User.objects.create_user(**validated_data)
            return user

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['id', 'name', 'description']

class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = ['id', 'name']



class ProductSerializer(serializers.ModelSerializer):
    tags=serializers.PrimaryKeyRelatedField(queryset=Tag.objects.all(),many=True)
    owner=UserSerializer(read_only=True)
    store=serializers.PrimaryKeyRelatedField(queryset=Store.objects.all(),required=False,allow_null=True)
    class Meta:
        model=Product
        fields="__all__"

    def create(self, validated_data):
        tags = validated_data.pop('tags', [])
        product = Product.objects.create(**validated_data)
        product.tags.set(tags)
        return product
    
    def get_product_image(self,obj):
        request=self.context.get('request')
        if obj.product_image:
            return request.build_absolute_url(obj.product_image.url)
        return None

class StoreSerializer(serializers.ModelSerializer):
    owner = UserSerializer(read_only=True)
    store_image = serializers.ImageField(required=False)  # Ajout essentiel

    class Meta:
        model = Store
        fields = [
            'id', 'name', 'description', 'owner',
            'created_at', 'updated_at', 'store_image',
        ]
    def get_store_image(self,obj):
        request=self.context.get('request')
        if obj.store_image:
            return request.build_absolute_url(obj.store_image.url)
        return None

class UserMiniSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['id','username',"profile_picture"]

class MessageCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = ['receiver', 'content']  # pas besoin d’inclure 'sender', il est défini dans perform_create()


class ConversationSerializer(serializers.ModelSerializer):
    last_message = serializers.SerializerMethodField()

    class Meta:
        model = Conversation
        fields = ['id', 'participants', 'created_at', 'last_message']

    def get_last_message(self, obj):
        last_msg = obj.messages.order_by('-created_at').first()
        return MessageSerializer(last_msg).data if last_msg else None

class MessageSerializer(serializers.ModelSerializer):
    sender=UserMiniSerializer()
    receiver=UserMiniSerializer()
    class Meta:
        model=Message
        fields='__all__'


class CartItemSerializer(serializers.ModelSerializer):
    product = serializers.PrimaryKeyRelatedField(queryset=Product.objects.all())  
    price = serializers.DecimalField(source='product.price', max_digits=10, decimal_places=2, read_only=True)  # Ajouter le prix du produit
    product_image=serializers.ImageField(source='product.product_image',read_only=True)
    cart = serializers.HiddenField(default=None)  

    class Meta:
        model = CartItem
        fields = ['id', 'product', 'quantity', 'price', 'cart','product_image']  # Inclure 'price'

class CartSerializer(serializers.ModelSerializer):
    items = CartItemSerializer(many=True, read_only=True)
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())  # Ajout ici

    class Meta:
        model = Cart
        fields = '__all__'

class OrderHistorySerializer(serializers.ModelSerializer):
    user=UserSerializer(read_only=True)
    class Meta:
        model=OrderHistory
        fields=[
            'id','product_name','user','price','store_name','bought_at'
        ]


class SuggestionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Suggestion
        fields = ['id', 'user', 'name', 'email', 'phone', 'message', 'created_at']