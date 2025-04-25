from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator

class User(AbstractUser):
    phone = models.CharField(max_length=15, null=True, blank=True)
    address = models.TextField(blank=True)
    ALLOWED_EXTENSIONS = ['bmp', 'dib', 'gif', 'jfif', 'jpe', 'jpg', 'jpeg', 'pbm', 'pgm', 'ppm', 'pnm', 'pfm', 'png', 'apng', 'blp', 'bufr', 'cur', 'pcx', 'dcx', 'dds', 'ps', 'eps', 'fit', 'fits', 'fli', 'flc', 'ftc', 'ftu', 'gbr', 'grib', 'h5', 'hdf', 'jp2', 'j2k', 'jpc', 'jpf', 'jpx', 'j2c', 'icns', 'ico', 'im', 'iim', 'mpg', 'mpeg', 'tif', 'tiff', 'mpo', 'msp', 'palm', 'pcd', 'pdf', 'pxr', 'psd', 'qoi', 'bw', 'rgb', 'rgba', 'sgi', 'ras', 'tga', 'icb', 'vda', 'vst', 'webp', 'wmf', 'emf', 'xbm', 'xpm']
    profile_picture = models.ImageField(
        upload_to='img/profile_pictures/',
        null=True,
        blank=True,
        validators=[FileExtensionValidator(allowed_extensions=ALLOWED_EXTENSIONS)]
    )
    bios=models.TextField(blank=True)

class Category(models.Model):
    name = models.CharField(max_length=255, unique=True)  # Un nom unique pour chaque catégorie
    description = models.TextField(blank=True, null=True)  # Description de la catégorie (optionnelle)
    def __str__(self):
        return self.name

class Tag(models.Model):
    name = models.CharField(max_length=255, unique=True)  # Un nom unique pour chaque tag
    def __str__(self):
        return self.name

CURRENCY_CHOICES=[
    ('CDF','Franc Congolais'),
    ('USD','Dollars Americain')
]
class Product(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, choices=CURRENCY_CHOICES, default='CDF')
    available = models.BooleanField(default=True)
    store = models.ForeignKey('Store', on_delete=models.CASCADE, related_name='products', null=True, blank=True)
    owner = models.ForeignKey('User', on_delete=models.CASCADE, related_name='products')
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True, related_name='products')  # Relier à Category
    tags = models.ManyToManyField(Tag, blank=True, related_name='products')  # Relier à Tag
    created_at = models.DateTimeField(auto_now_add=True)
    product_image = models.ImageField(upload_to='img/product_images', null=True, blank=True)
    publish_in_store = models.BooleanField(default=False)

    def is_user_product(self):
        return not self.publish_in_store or self.store is None

    def save(self, *args, **kwargs):
        if self.publish_in_store and not self.store:
            raise ValueError("Un produit publié dans un store doit avoir un store assigné.")
        if not self.publish_in_store:
            self.store = None
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name


class Store(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    owner = models.ForeignKey('User', on_delete=models.CASCADE, related_name='stores')  # Nom unique
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)
    store_image = models.ImageField(upload_to="img/store_images/",null=True)
    is_public=models.BooleanField(default=False)
    
    def __str__(self):
        return self.name

class Message(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sent_messages")
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name="received_messages")
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    conversation = models.ForeignKey("Conversation", on_delete=models.CASCADE, related_name="messages", null=True)
    
    def __str__(self):
        return f"{self.sender.username}: {self.content[:30]}"

        
class Conversation(models.Model):
    participants = models.ManyToManyField('User')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Conversation entre {[user.username for user in self.participants.all()]}"

class Cart(models.Model):
    user = models.ForeignKey('User', on_delete=models.CASCADE, related_name='cart')

class CartItem(models.Model):
    cart = models.ForeignKey('Cart', on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey('Product', on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)
    
    def __str__(self):
        return f"{self.quantity} x {self.product.name}"

class OrderHistory(models.Model):
    user = models.ForeignKey('User', on_delete=models.CASCADE, related_name='purchase_history')  # Nom unique
    product_name = models.CharField(max_length=255)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    store_name = models.CharField(max_length=255, null=True, blank=True)
    bought_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.user.username} - {self.product_name}"

# models.py
class Suggestion(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)  # Référence à l'utilisateur qui a fait la suggestion
    name = models.CharField(max_length=100)  # Nom de l'utilisateur
    email = models.EmailField(max_length=255)  # Email de l'utilisateur
    phone = models.CharField(max_length=20)  # Numéro de téléphone de l'utilisateur
    message = models.TextField()  # Contenu du message de la suggestion
    created_at = models.DateTimeField(auto_now_add=True)  # Date de création de la suggestion

    def __str__(self):
        return f'Suggestion de {self.name} - {self.created_at}'