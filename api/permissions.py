from rest_framework.permissions import BasePermission,SAFE_METHODS

class IsOwnerOrReadOnly(BasePermission):
    """Permet la lecture à tout le monde mais l'edition uniquement au proprio de l'obj"""
    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True
        return obj.user==request.user
        
class IsAuthenticatedAndOwner(BasePermission):
    """Seul le proprietaire peut acceder/modifier/supprimer """
    def has_object_permission(self, request, view, obj):
        return obj.user==request.user
    
class IsAuthenticated(BasePermission):
    """seul les utilisateurs connectes peuvent acceder a cette ressource."""
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated